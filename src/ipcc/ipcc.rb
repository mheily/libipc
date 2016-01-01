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
    attr_accessor :name, :type

    def initialize(spec)
      @spec = spec
      @name = spec.keys[0]
      @type = spec.values[0]
    end
    
    def pointer?
      type =~ /\*$/ ? true : false
    end

    def copy_in(argc)
      tok = []
      case type
      when 'char *'
        tok << "iov_in[#{argc}].iov_base = #{name};"
        tok << "iov_in[#{argc}].iov_len = (#{name} == NULL) ? 0 : strlen(#{name}) + 1;"
      when /\A[u]int\d+_t\z/, /(unsigned )?(long |int )?(int|long|char)/, 'float', 'double', 'long double',
           /\Astruct [A-Za-z0-9_]+\z/
        tok << "iov_in[#{argc}].iov_base = &#{name};"
        tok << "iov_in[#{argc}].iov_len = sizeof(#{name});"
      else
        raise 'Unknown datatype; need to specify the calling convention'
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
      @accepts = spec['accepts'].map { |a| Argument.new(a) }
      @returns = spec['returns'].map { |a| Argument.new(a) }
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

    def data_structures
      <<__EOF__
struct ipc_request__#{name} {
#{
  format = "\t%-8s %s;"
  tok = []
  tok << "\tstruct ipc_message_header _ipc_hdr;"
  @accepts.each do |arg|
    tok << sprintf(format, arg.type, arg.name)
  end
  tok << sprintf(format, "char",  "_ipc_buf[]")
  tok.join("\n")
}
};

struct ipc_response__#{name} {
#{
  format = "\t%-8s %s;"
  tok = []
  tok << "\tstruct ipc_message_header _ipc_hdr;"
  @returns.each do |arg|
    tok << sprintf(format, arg.type, arg.name)
  end
  tok << sprintf(format, "char",  "_ipc_buf[]")
  tok.join("\n")
}
};
__EOF__
    end 

    def skeleton_prototype
      "int #{stub_name}(int s, char *request_buf, size_t request_sz)"
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
      tok << "iov_in[0].iov_base = &request._ipc_hdr;"
      tok << "iov_in[0].iov_len = sizeof(request._ipc_hdr);"
      argc = 1
      @accepts.each do |arg|
        tok.concat(arg.copy_in(argc))
        argc += 1
      end

      # Set the method ID
      tok << '' << "/* Set the header variables */"
      bufsz_tok = "request._ipc_hdr._ipc_bufsz = 0"
      0.upto(@accepts.length) { |idx| bufsz_tok += " + iov_in[#{idx}].iov_len" }
      tok << bufsz_tok + ';'
      tok << "request._ipc_hdr._ipc_method = #{method_id};"

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
          tok << "*#{ident} = response.#{ident}"
	else
	  raise 'Unknown datatype; need to specify the calling convention'
	end
        count += 1
      end
      tok << ''
      tok.join(";\n\t")
    end
    
    # The arguments to the real function, as defined within the skeleton
    def archetype_args
      tok = []
      tok << "\n"
      tok << @returns.map do |ent|
        if ent.pointer?
          'NULL /* FIXME: string deref */'
        else
          "&response.#{ent.name}"
        end
      end.map { |s| "\t\t#{s}" }.join(",\n")
      tok << ",\n"
      tok << @accepts.map do |ent|
        if ent.pointer?
          'NULL /* FIXME: string deref */'
        else
          "request->#{ent.name}"
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
      ERB.new(template).result(binding)
    end

    def to_c_stub_source
      template = <<__EOF__
/* Automatically generated by ipcc(1) -- do not edit */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
        
#include <ipc.h>
      
<%= @methods.map { |method| method.data_structures }.join("\n\n") %>

<% @methods.each do |method| %>
<%= method.prototype  %>
{
	struct ipc_request__<%= method.name %> request;
	struct ipc_response__<%= method.name %> response;
	int fd = -1;
	int rv = 0;
	char *buf = NULL;
	size_t bufsz = 0;
	off_t bufpos = 0;
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
	if (bytes < request._ipc_hdr._ipc_bufsz) {
	  rv = -73; /* FIXME: need an error code / logging */
	  goto out; 
	}
  
	if (write(fd, buf, bufsz) < bufsz) {
		rv = IPC_CAPTURE_ERRNO;;
		goto out;
	}

	free(buf);
	buf = NULL;

	if (read(fd, &response, sizeof(response)) < sizeof(response)) {
		rv = IPC_CAPTURE_ERRNO;
		goto out;
	}

	if (response._ipc_hdr._ipc_bufsz > 0) {
		buf = malloc(response._ipc_hdr._ipc_bufsz);
		if (!buf) {
			rv = -IPC_ERROR_NO_MEMORY;
			goto out;
		}
	}
	<%= method.rets_copy_out.chomp %>

out:
	free(buf);
	close(fd);
	return rv;
}
<% end %>
__EOF__
      ERB.new(template).result(binding)
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

int ipc_dispatch__#{identifier}(int, char *, size_t);

#{@methods.map { |method| method.prototype.gsub('ipc_stub__', 'ipc_skeleton__') }.join("\n")};

#endif /* !#{include_guard_name} */
__EOF__
      ERB.new(template).result(binding)
    end
    
  def to_c_source
    template = <<__EOF__
/* Automatically generated by ipcc(1) -- do not edit */

#include <stdlib.h>
#include <string.h>

#include <ipc.h>

<%= @methods.map { |method| method.prototype }.join(";\n\n") + ";\n\n" %>

<%= @methods.map { |method| method.archetype }.join("\n\n") %>

<%= @methods.map { |method| method.data_structures }.join("\n\n") %>

int ipc_dispatch__#{identifier}(int s, char *request_buf, size_t request_sz)
{
  struct ipc_message_header *header = (struct ipc_message_header *) request_buf;
	int (*method)(int, char *, size_t);

	switch (header->_ipc_method) {
<% @methods.map do |method| %>
		case <%= method.method_id %>:
			method = &<%= method.stub_name %>;
			break;	
<% end %>
		default:
			return -IPC_ERROR_METHOD_NOT_FOUND;
			/* NOTREACHED */
	}
	return (*method)(s, request_buf, request_sz);
}

<% @methods.each do |method| %>
<%= method.prototype  %>
{
	struct ipc_request__<%= method.name %> *request;
	struct ipc_response__<%= method.name %> response;
	int rv = 0;
	char *buf = NULL;
	size_t bufsz = 0;
	off_t bufpos = 0;

	request = (struct ipc_request__<%= method.name %> *) request_buf;

	/* Call the real function */
	rv = <%= method.name %>(<%= method.archetype_args %>);

	/* Copy out the results*/
	//TODO

	free(buf);
	buf = NULL;

	/* Send the response */
	if (write(s, &response, sizeof(response)) < sizeof(response)) {
		rv = -1; /* TODO: capture errno here */
		goto out;
	}

	/* Send the variable-length data, if there is any */
	if (response._ipc_hdr._ipc_bufsz > 0) {
		buf = malloc(response._ipc_hdr._ipc_bufsz);
		if (!buf) {
			rv = -IPC_ERROR_NO_MEMORY;
			goto out;
		}
		if (write(s, buf, bufsz) < bufsz) {
			rv = -1; /* TODO: capture errno here */
			goto out;
		}
	}

out:
	free(buf);
	close(s);
	return rv;
}
<% end %>
__EOF__
    ERB.new(template).result(binding)
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
