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
    attr_accessor :name, :type, :index

    def initialize(spec, index)
      @spec = spec
      @index = index
      @name = spec.keys[0]
      @type = spec.values[0]
    end
    
    def pointer?
      type =~ /\*$/ ? true : false
    end

    # Copy in for stubs
    def copy_in
      tok = []
      case type
      when 'char *'
        tok << "iov_in[#{index}].iov_base = #{name};"
        tok << "iov_in[#{index}].iov_len = (#{name} == NULL) ? 0 : strlen(#{name}) + 1;"
      when /\A[u]int\d+_t\z/, /(unsigned )?(long |int )?(int|long|char)/, 'float', 'double', 'long double',
           /\Astruct [A-Za-z0-9_]+\z/
        tok << "iov_in[#{index}].iov_base = &#{name};"
        tok << "iov_in[#{index}].iov_len = sizeof(#{name});"
      else
        raise 'Unknown datatype; need to specify the calling convention'
      end
      tok
    end
    
    def skeleton_copy_in
      tok = []
      if pointer?
        raise 'TODO'
      else
        tok << "#{type} arg_#{name} = *((#{type} *) pos);"
        tok << "pos += request->_ipc_argsz[#{index}];"
      end
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
      @accepts = spec['accepts'].map { |a|
        index += 1
        Argument.new(a, index)
      }
      index = 0
      @returns = spec['returns'].map { |a|
        index += 1
        Argument.new(a, index)
      }
      raise "method #{name}: id is required" unless @method_id
    end

    # Convert the name into a legal C identifier
    def identifier
      name.gsub(/[^A-Za-z0-9_]/, '_')
    end
    
    # Return the macro definition of the stub
    def stub_name
      prefix = @service.kind_of?(Skeleton) ? 'skeleton' : 'stub'
      'ipc_' + prefix + '__' + service.identifier + '__' + identifier
    end
    
    def stub_macro
      sprintf "#define %-16s %s\n", name, stub_name
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
  tok << ["\t/* returns */\n\t"]
  tok << @returns.map { |ent| "#{ent.type} *#{ent.name}" }.join(', ')
  tok << ", "
  tok << "\n\t/* accepts */\n\t"
  tok << @accepts.map { |ent| "#{ent.type} #{ent.name}" }.join(', ')
  tok.join
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
        @returns.map { |ent| "#{ent.type} *#{ent.name}" },
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
      @accepts.each do |arg|
        tok.concat(arg.copy_in)
      end

      # Fill in the message header
      tok << '' << "/* Set the header variables */"
      bufsz_tok = "request._ipc_bufsz = 0"
      @accepts.each { |arg| bufsz_tok += " + iov_in[#{arg.index}].iov_len" }
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
      tok.map { |s| "\t#{s}\n" }.join('')
    end

    def rets_copy_out
      count = 0
      tok = []
      @returns.each do |arg|
        ident = arg.name
        type = arg.type

	case type
	when 'char **'
	  # Lame initial attempt:
          #tok << "*#{ident} = malloc(4096);"
          #tok << "iov_out[#{count}].iov_base = *#{ident}"
          #tok << "iov_out[#{count}].iov_len = 4096"
	  raise "FIXME -- it will be possible to overflow iov_base and break everything"
	  raise "FIXME -- this will leak memory if the call fails"
	when /\A[u]int\d+_t\z/, /(unsigned )?(long |int )?(int|long|char)/, 'float', 'double', 'long double'
          tok << "*#{ident} = *((#{type} *)pos);"
          tok << "pos += sizeof(*#{ident});"
	else
	  raise 'Unknown datatype; need to specify the calling convention'
	end
        count += 1
      end
      tok
    end
    
    # The arguments to the real function, as defined within the skeleton
    def archetype_args
      tok = []
      tok << "\n"
      tok << @returns.map do |ent|
        if ent.pointer?
          'NULL /* FIXME: string deref */'
        else
          "&ret_#{ent.name}"
        end
      end.map { |s| "\t\t#{s}" }.join(",\n")
      tok << ",\n"
      tok << @accepts.map do |ent|
        if ent.pointer?
          'NULL /* FIXME: string deref */'
        else
          "arg_#{ent.name}"
        end
      end.map { |s| "\t\t#{s}" }.join(",\n")
      tok.join
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
/* Automatically generated by ipcc(1) -- do not edit */
#ifndef #{include_guard_name}
#define #{include_guard_name}

#include <ipc.h>

#{@methods.map { |method| method.stub_macro }.join("\n")}
      
#{@methods.map { |method| method.prototype }.join("\n")};

#endif /* !#{include_guard_name} */
__EOF__
      ERB.new(template, nil, '<>').result(binding)
    end

    def to_c_stub_source
      template = <<__EOF__
/* Automatically generated by ipcc(1) -- do not edit */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
        
#include <ipc.h>
      
<% @methods.each do |method| %>
<%= method.prototype  %>
{
	struct ipc_message request;
	struct ipc_message response;
	char *buf = NULL;
	int fd = -1;
	int rv = 0;
	ssize_t bytes;

	fd = ipc_connect(<%= method.service.domain %>, "<%= method.service.name %>");
	if (fd < 0) { 
		rv = -IPC_ERROR_CONNECTION_FAILED;
		goto out;
	}

	<%= method.args_copy_in.chomp %>
  
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

	/* TODO: validate the response */
	
	if (response._ipc_bufsz > 0) {
		buf = malloc(response._ipc_bufsz);
		if (!buf) {
			rv = -IPC_ERROR_NO_MEMORY;
			goto out;
		}
		if (read(fd, buf, response._ipc_bufsz) < response._ipc_bufsz) {
			rv = IPC_CAPTURE_ERRNO;
			goto out;
		}
		void *pos = buf;
		<%= method.rets_copy_out.join("\t\t\n") + "\n" %>
	}

out:
	free(buf);
	close(fd);
	return rv;
}
<% end %>
__EOF__
      ERB.new(template, nil, '<>').result(binding)
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
/* Automatically generated by ipcc(1) -- do not edit */
#ifndef #{include_guard_name}
#define #{include_guard_name}

#include <ipc.h>

int ipc_dispatch__#{identifier}(int, struct ipc_message *, char *);

#{@methods.map { |method| method.prototype.gsub('ipc_stub__', 'ipc_skeleton__') }.join("\n")};

#endif /* !#{include_guard_name} */
__EOF__
      ERB.new(template, nil, '<>').result(binding)
    end
    
  def to_c_source
    template = <<__EOF__
/* Automatically generated by ipcc(1) -- do not edit */

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

	response._ipc_bufsz = 0;
	iov_out[0].iov_base = &response;
	iov_out[0].iov_len = sizeof(response);
	<%
	count = 1 
	method.returns.each do |ret| 
	%>
	<%= ret.type %> ret_<%= ret.name %>;
	iov_out[<%= count %>].iov_base = &ret_<%= ret.name %>;
	iov_out[<%= count %>].iov_len = sizeof(ret_<%= ret.name %>);
	response._ipc_bufsz += sizeof(ret_<%= ret.name %>);
	<%
	  count += 1 
	end 
	%>
	
	/* Copy in arguments */
	void *pos = body;
	<% methods.each do |method| %>
	<%= method.accepts.map { |arg| arg.skeleton_copy_in }.join("\t\n") %>
	<% end %>
	
	/* Call the real function */
	rv = <%= method.name %>(<%= method.archetype_args %>);

	/* Send the response */
	bytes = writev(s, (struct iovec *) &iov_out, <%= method.returns.length + 1%>);
	if (bytes < 0) {
		rv = -1; /* TODO: capture errno here */
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
    ERB.new(template, nil, '<>').result(binding)
  end
          
  private
  
    def include_guard_name
      'IPC_SKELETON_' + @name.upcase.gsub(/[^A-Z0-9]/, '_') + '_H'
    end
  end

  class CodeGenerator
    
    attr_accessor :language, :outdir
    
    def initialize(spec)
      @service = Service.new(spec)
      @skeleton = Skeleton.new(spec)
      @outdir = nil
      @language = 'c'
    end
    
    def generate
      raise 'must specify output directory' unless @outdir
      File.open("#{@outdir}/#{@service.identifier}.stub.h", "w+") do |f|
        f.puts @service.to_c_stub_header
      end
      File.open("#{@outdir}/#{@service.identifier}.stub.c", "w+") do |f|
        f.puts @service.to_c_stub_source
      end
      File.open("#{@outdir}/#{@service.identifier}.skeleton.h", "w+") do |f|
        f.puts @skeleton.to_c_header
      end
      File.open("#{@outdir}/#{@service.identifier}.skeleton.c", "w+") do |f|
        f.puts @skeleton.to_c_source
      end
    end
  end
end

    
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: example.rb [options]"

  opts.on("--c-out DIR", "Generate C code in the directory DIR") do |dir|
    options[:outdir] = dir
    options[:language] = 'c'
  end
end.parse!
    
ARGV.each do |arg|
  codegen = IPC::CodeGenerator.new(YAML.load(File.read(arg)))
  codegen.outdir = options[:outdir]
  codegen.generate
end
