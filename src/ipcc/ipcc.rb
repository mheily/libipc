#!/usr/bin/env ruby
#
# Copyright (c) 2015 Mark Heily <mark@heily.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

require 'erb'
require 'optparse'
require 'yaml'
require 'pp'

module IPC

  class Argument
    attr_accessor :name, :type, :index, :pass_by

    def initialize(index, name, type, pass_by)
      @index = index + 1   # KLUDGE, because argument 0 is the ipc_session object 
      @name = 'arg_' + name
      @type = type
      @pass_by = pass_by
    end
    
    def pointer?
      @pass_by == :reference
    end
    
    def base_type
      @pass_by == :reference ? type : type.gsub(/ \*$/, '')
    end

    def return_type
      type
    end

    # Copy in for stubs
    def copy_in(iovec)
      tok = []
      case return_type
      when 'char *'
        tok << "#{iovec}.iov_base = #{name};"
        tok << "#{iovec}.iov_len = (#{name} == NULL) ? 0 : strlen(#{name}) + 1;"
      when /\A[u]int\d+_t\z/, /(unsigned )?(long |int )?(int|long|char)/, 'float', 'double', 'long double',
           /\Astruct [A-Za-z0-9_]+\z/
        tok << "#{iovec}.iov_base = &#{name};"
        tok << "#{iovec}.iov_len = sizeof(#{name});"
      else
        raise 'Unknown datatype; need to specify the calling convention'
      end
      tok
    end
    
    # Copy out for stubs?
    def copy_out(iovec, argsz)
      tok = []
      if type == 'char **'
        tok << "char *tmp_#{name} = malloc(#{argsz});"
        tok << "#{iovec}.iov_base = tmp_#{name};"
        tok << "#{iovec}.iov_len = #{argsz};"
      else
        tok << "#{iovec}.iov_base = #{name};"
        tok << "#{iovec}.iov_len = sizeof(*#{name});"
      end
      tok
    end

    def returns_to_iovec(iovec, argsz)
      tok = []
    end

    def skeleton_copy_in
      tok = []
      if @type == 'char *'
        tok << "#{return_type} #{name} = (#{type}) pos;"
      else
        tok << "#{return_type} #{name} = *((#{type} *) pos);"
      end
      tok << "pos += request->_ipc_argsz[#{index - 1}];"
      tok
    end
  end

  class Method
    attr_accessor :accepts, :returns, :name, :service, :method_id

    def initialize(service, name, spec)
      @service = service
      @name = name
      @spec = spec
      @method_id = spec['id']
      index = 0
      @prototype = spec['prototype']
      raise "method #{name}: prototype is required" unless @prototype
      raise "method #{name}: id is required" unless @method_id
      parse_prototype
    end

    # Given a C function prototype, parse it into a list of @accepts and @returns
    def parse_prototype
      tok = @prototype.scan(/[A-Za-z0-9]+|[\(\),]|\*+/)
      #pp tok
      
      @return_type = tok.shift
      raise "only 'int' return types are supported at the current time" unless @return_type == 'int'
      
      @server_method = tok.shift
      raise "syntax error in: #{@prototype}" unless tok.shift == '('
      
      args = []
      arg = { :pass_by => :value, :ident => nil, :type => nil }
      node = nil 
      until node == ')'
        node = tok.shift
        case node
        when ')'
          break
        when '**'
          arg[:pass_by] = :reference # assumes 'char **'
          arg[:type] += ' **'
        when '*'
          arg[:pass_by] = :reference if arg[:type] != 'char'
          arg[:type] += ' *'
        when /u?int(8|16|32|64)_t/, 'int', 'long', 'bool', 'void', 'char'
          arg[:type] = node
        when 'const'
          # ignored, for now
        when ','
          args.push(arg.dup)
          arg = { :pass_by => :value, :ident => nil, :type => nil }
        when /[A-Za-z0-9]+/
          arg[:ident] = node
        else
          raise "syntax error in: #{@prototype}, node=#{@node}"
        end
      end
      args.push(arg)
      #pp args
      
      @accepts = []
      @returns = [] 
      for i in 0.upto(args.length - 1)
        arg = Argument.new(i, args[i][:ident], args[i][:type], args[i][:pass_by])
        if arg.pass_by == :value
          @accepts << arg
        else
          @returns << arg
        end
      end
      #pp @accepts
      #pp @returns
    end
    
    # Convert the name into a legal C identifier
    def identifier
      name.gsub(/[^A-Za-z0-9_]/, '_')
    end
    
    # Return the macro definition of the stub
    def stub_name
      prefix = @service.kind_of?(Skeleton) ? 'skeleton' : 'stub'
      'ipc_' + prefix + '__' + service.identifier + '__method_' + method_id.to_s
    end
    
    def signature(ident = '')
      tok = []
      tok << 'int (*' + ident + ')(' 
      tok << [
          'struct ipc_session *',
          @returns.map { |ent| ent.type },
          @accepts.map { |ent| ent.type },
      ].flatten.join(', ')
      tok << ')'
      tok.join  
    end
    
    def parameters
      tok = []
      tok.concat @returns.map { |ent| "#{ent.type} #{ent.name}" }
      tok.concat @accepts.map { |ent| "#{ent.type} #{ent.name}" }
      tok.join(', ')
    end

    def marshall_parameters(session)
      tok = []
      tok << session
      tok.concat @returns.map { |ent| ent.name }
      tok.concat @accepts.map { |ent| ent.name }
      tok.join(', ')
    end
        
    def inline_stub
      tok = []
      tok.concat [
        'static inline int',
        name + '(' + parameters + ')',
        '{',
      ]
      tok.concat [
        'struct ipc_session *session;',
        signature('stub') + ';',
        '',
        'session = ipc_client_connect(NULL, ' + service.domain + 
            ', "' + service.name + '");',
        'if (!session) return -IPC_ERROR_CONNECTION_FAILED;',
        'stub = (' + signature + ') ipc_session_stub(session, ' + method_id.to_s + ');',
        'if (!stub) return -IPC_ERROR_METHOD_NOT_FOUND;', 
        'return ((*stub)(' + marshall_parameters("session") + '));',
      ].map { |line| "\t#{line}" }
      tok << '}'
      tok.join("\n")  
    end

    def skeleton_prototype
      "int #{stub_name}(int s, struct ipc_message *request, char *body)"
    end
    
    def prototype
      return skeleton_prototype if @service.kind_of?(Skeleton)
      template = <<__EOF__
int #{stub_name}(
#{
  tok = []
  tok << 'struct ipc_session *session'
  tok.concat @returns.map { |ent| "#{ent.return_type} #{ent.name}" }
  tok.concat @accepts.map { |ent| "#{ent.type} #{ent.name}" }
  tok.map { |line| "\t#{line}" }.join(', ')
})
__EOF__
    template.chomp
    end

    # The "archetype" is a clever name for the declaration of the original method
    # that the IPC mechanism is a wrapper for.
    def archetype
      tok = []
      tok << 'extern int ' + name
      tok << '(' + "\n"
      tok << [
        @returns.map { |ent| "#{ent.type} #{ent.name}" },
        @accepts.map { |ent| "#{ent.type} #{ent.name}" },
      ].flatten.map { |s| "\t" + s }.join(",\n")
      tok << "\n);"
      tok.join
    end
    
    def args_copy_in
      tok = []
      
      tok << "struct iovec iov_in[#{@accepts.length + 1}];"
      tok << "iov_in[0].iov_base = &request;"
      tok << "iov_in[0].iov_len = sizeof(request);"
      for i in 0.upto(@accepts.length - 1)
        tok.concat(@accepts[i].copy_in("iov_in[#{i + 1}]"))
      end

      # Fill in the message header
      tok << '' << "/* Set the header variables */"
      bufsz_tok = "request._ipc_bufsz = 0"
      @accepts.each { |arg| bufsz_tok += " + iov_in[#{arg.index - 1}].iov_len" }
      tok << bufsz_tok + ';'
      tok << "request._ipc_method = #{method_id};"
      tok << "request._ipc_argc = #{@accepts.length};"
      tok << "memset(&request._ipc_argsz, 0, " +
        "sizeof(request._ipc_argsz));"
      count = 0
      @accepts.each do |arg|
        tok << "request._ipc_argsz[#{count}] = iov_in[#{count + 1}].iov_len;"
        count += 1
      end
      tok << ''
      tok
    end
    
    # The arguments to the real function, as defined within the skeleton
    def archetype_args
      tok = []
      @returns.map { |ent| tok << "&#{ent.name}" }
      @accepts.map { |ent| tok << ent.name }
      tok.join(', ')
    end
    
    # Copy out for stubs?
    def copy_out(iovec, response)
      tok = []
      tok << "struct iovec #{iovec}[#{returns.length}];"
      iov_count = 0
      @returns.each do |arg|
        tok << arg.copy_out("#{iovec}[#{iov_count}]", "#{response}._ipc_argsz[#{iov_count}]")
        iov_count += 1
      end
      tok
    end

  end

  class Service
    attr_accessor :version, :name, :domain, :methods, :vtable

    def initialize(spec)
      @version = spec['version']
      @name = spec['service']
      @domain = spec['domain']
      @methods = spec['methods'].map do |name, body|
        Method.new(self, name, body)
      end
    end

    # A table to help convert method IDs into method function pointers
    def vtable
      tok = []
      tok << "const struct {"
      tok << "\t" + "int vt_id;"
      tok << "\t" + "void (*vt_method)(int);"
      tok << "} ipc_#{identifier}_vtable[] = {"
      tok << @methods.map do |method|
        "#{method.method_id}, &#{method.stub_name},\n" 
      end.join("\n")
      tok << '};'
      tok.join("\n") 
    end

    # Convert the name into a legal C identifier
    def identifier
      name.gsub(/[^A-Za-z0-9_]/, '_')
    end

    def to_c_stub_header
      template = <<__EOF__
#ifndef #{include_guard_name}
#define #{include_guard_name}

/* TODO: need to allow the inclusion of app domain-specific headers here */

#include <ipc.h>

#{@methods.map { |method| method.inline_stub }.join("\n")}
     
#endif /* !#{include_guard_name} */
__EOF__
      ERB.new(template, nil, '<>').result(binding)
    end

    def to_c_stub_source
      template = <<__EOF__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
        
#include <ipc.h>
      
<% @methods.each do |method| %>
<%= method.prototype %>
{
	struct ipc_message request;
	struct ipc_message response;
	char *buf = NULL;
	int fd = -1;
	int rv = 0;
	ssize_t bytes;
	
	fd = ipc_session_fd(session);

<% method.args_copy_in.each do |line| -%>
	<%= line %>
<% end -%>
  
	bytes = writev(fd, (struct iovec *) &iov_in, <%= method.accepts.length + 1 %>);
	if (bytes < 0) {
		rv = IPC_CAPTURE_ERRNO;
		goto out;
	}
	if (bytes < request._ipc_bufsz) {
		rv = -73; /* FIXME: need an error code / logging */
		goto out; 
	}

	if (read(fd, &response, sizeof(response)) < sizeof(response)) {
		rv = IPC_CAPTURE_ERRNO;
		goto out;
	}

	rv = ipc_message_validate(&response);
	if (rv < 0) goto out;
	
	if (response._ipc_bufsz > 0) {
<% method.copy_out("iov", "response").flatten.each do |line| -%>
<%= "\t\t" + line %>
<% end -%>
		if (readv(fd, (struct iovec *) &iov, <%= method.returns.length %>) < response._ipc_bufsz) {
			rv = IPC_CAPTURE_ERRNO;
			goto out;
		}
<% method.returns.each do |arg| -%>
<%  if arg.type == 'char **' -%>
		if (response._ipc_argsz[<%= arg.index - 1%>] == 0) {
			free(tmp_<%= arg.name %>);
			<%= arg.name %> = NULL;
		} else {
      *<%= arg.name %> = tmp_<%= arg.name %>;
			*<%= arg.name %>[response._ipc_argsz[<%= arg.index - 1 %>] -1] = '\\0';
		}
<%  end -%>
<% end -%>
	}

out:
	free(buf);
	close(fd);
	return rv;
}
<% end %>
__EOF__
      ERB.new(template, nil, '-<>').result(binding)
    end

    private

    def include_guard_name
      'IPC_STUB_' + @name.upcase.gsub(/[^A-Z0-9]/, '_') + '_H'
    end
  end
  
  # Generated code executed on the server-side
  class Skeleton < Service
    def to_c_header
      template = <<__EOF__
#ifndef #{include_guard_name}
#define #{include_guard_name}

#include <ipc.h>

int ipc_dispatch__#{identifier}(int, struct ipc_message *, char *);

#{
      if false
      @methods.map { |method| method.prototype.gsub('ipc_stub__', 'ipc_skeleton__') }.join("\n")
      end
      };

#endif /* !#{include_guard_name} */
__EOF__
      ERB.new(template, nil, '<>').result(binding)
    end
    
  def to_c_source
    template = <<__EOF__

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
    
#include <ipc.h>

<%= @methods.map { |method| method.prototype }.join(";\n\n") + ";\n\n" %>

<%= @methods.map { |method| method.archetype }.join("\n\n") %>

int ipc_dispatch__#{identifier}(int s, struct ipc_message *request, char *body)
{
	int (*method)(int, struct ipc_message *, char *);

	switch (request->_ipc_method) {
<% @methods.map do |method| %>
		case <%= method.method_id %>:
			method = &<%= method.stub_name %>;
			break;	
<% end %>
		default:
			return -IPC_ERROR_METHOD_NOT_FOUND;
			/* NOTREACHED */
	}
	return (*method)(s, request, body);
}

<% @methods.each do |method| %>
<%= method.prototype  %>
{
	int rv = 0;
	struct ipc_message response;
	struct iovec iov_in[<%= method.accepts.length %>];
	struct iovec iov_out[<%= method.returns.length + 1%>];
	ssize_t bytes;

	/* Setup temporary variables to hold the return values */
<% method.returns.each do |ret| -%>
	<%= ret.type.gsub(/\\*\\z/, '') %> <%= ret.name %>;
<% end -%>
	
	/* Copy in arguments */
	void *pos = body;
<% method.accepts.map { |arg| arg.skeleton_copy_in }.flatten.each do |line| -%>
	<%= line %>
<% end -%>
	
	/* Call the real function */
	rv = <%= method.name %>(<%= method.archetype_args %>);
  
	/* Prepare the response */
	iov_out[0].iov_base = &response;
	iov_out[0].iov_len = sizeof(response);
	response._ipc_bufsz = 0;
	response._ipc_method = request->_ipc_method;
	response._ipc_argc = <%= method.returns.length %>;
	memset(&response._ipc_argsz, 0, sizeof(response._ipc_argsz));
<% method.returns.each do |ret| -%>
<% if ret.type == 'char **' -%>
	iov_out[<%= ret.index %>].iov_base = <%= ret.name %>;
	iov_out[<%= ret.index %>].iov_len = strlen(<%= ret.name %>) + 1;
<% else -%>
	iov_out[<%= ret.index %>].iov_base = &<%= ret.name %>;
	iov_out[<%= ret.index %>].iov_len = sizeof(<%= ret.name %>);
<% end -%>
	response._ipc_argsz[<%= ret.index - 1 %>] = iov_out[<%= ret.index %>].iov_len;
	response._ipc_bufsz += iov_out[<%= ret.index %>].iov_len;
<% end -%>   
      
	/* Send the response */
	bytes = writev(s, (struct iovec *) &iov_out, <%= method.returns.length + 1%>);
	if (bytes < 0) {
		rv = IPC_CAPTURE_ERRNO;
		goto out;
	}
	if (bytes < response._ipc_bufsz) {
		rv = -1; /* TODO: return code for a short write */
		goto out;
	}

out:
	close(s);
	return rv;
}
<% end %>
__EOF__
    ERB.new(template, nil, '-<>').result(binding)
  end
          
  private
  
    def include_guard_name
      'IPC_SKELETON_' + @name.upcase.gsub(/[^A-Z0-9]/, '_') + '_H'
    end
  end

  class CodeGenerator
    
    attr_accessor :language, :outdir, :cflags, :ldflags, :debug
    
    def initialize(spec)
      @service = Service.new(spec)
      @skeleton = Skeleton.new(spec)
      @outdir = nil
      @language = 'c'
      @cflags = ''
      @ldflags = ''
      @debug = false
    end
    
    def generate
      raise 'must specify output directory' unless @outdir
      File.open("#{@outdir}/#{@service.identifier}.h", "w+") do |f|
        f.puts "/* Automatically generated by ipcc(1) -- do not edit */\n"
        f.puts @service.to_c_stub_header
        #DEADWOOD: f.puts @skeleton.to_c_header
      end
      @skeleton_source = "#{@outdir}/#{@service.identifier}.ipc-skeleton.c" 
      File.open(@skeleton_source, "w+") do |f|
        f.puts "/* Automatically generated by ipcc(1) -- do not edit */\n"
        f.puts @skeleton.to_c_source
      end
      @stub_source = "#{@outdir}/#{@service.identifier}.ipc-stub.c" 
      File.open(@stub_source, "w+") do |f|
        f.puts "/* Automatically generated by ipcc(1) -- do not edit */\n"
        f.puts @service.to_c_stub_header
        f.puts @service.to_c_stub_source
      end  
    end
    
    def libipc_ldadd
      @debug ? '-lipc_debug' : '-lipc'
    end
      
    def compile
      cmd = "cc -shared -fPIC -g -O0 #{@cflags} #{@ldflags} " +
            "-o #{@outdir}/#{@service.identifier}.stub #{@stub_source}"
      puts cmd
      system cmd or raise 'command failed'
      
      cmd = "cc -shared -fPIC -g -O0 #{@cflags} #{@ldflags} " +
            "-o #{@outdir}/#{@service.identifier}.skeleton #{@skeleton_source}"
      puts cmd
      system cmd or raise 'command failed'
    end
      
  end
end

    
options = {
  :cflags => '',
  :ldflags => '',
  :debug => false,
}
OptionParser.new do |opts|
  opts.banner = "Usage: example.rb [options]"

  opts.on("--cflags FLAGS", "Pass additional flags to the compiler") do |flags|
    options[:cflags] = flags
  end
  opts.on("--ldflags FLAGS", "Pass additional flags to the linker") do |flags|
    options[:ldflags] = flags
  end
  opts.on("--c-out DIR", "Generate C code in the directory DIR") do |dir|
    options[:outdir] = dir
    options[:language] = 'c'
  end
  opts.on("--debug", "Link against a debug-enabled version of libipc") do
    options[:debug] = true
  end
end.parse!
    
ARGV.each do |arg|
  codegen = IPC::CodeGenerator.new(YAML.load(File.read(arg)))
  codegen.outdir = options[:outdir]
  codegen.cflags = options[:cflags]
  codegen.ldflags = options[:ldflags]
  codegen.debug = options[:debug]
  codegen.generate
  codegen.compile
end
