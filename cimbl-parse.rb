#! /usr/bin/env ruby
#
# @author Ollivier Robert <ollivier.robert@eurocontrol.int>
# @copyright © 2017 by Ollivier Robert for DG/CSS
#

require 'csv'
require 'optparse'

require 'dbi/dbrc'
require 'gettext'
require 'httpclient'

# Global data
#
MYNAME = File.basename($0)
ID = "0.0.1"

# Extensions already blocked
# cf. https://coll.eurocontrol.int/sites/InfoSec/SitePages/FAQMF.aspx

EXTS = [".apk", ".app", ".bat", ".cab",
        ".chm", ".cmd", ".com", ".dll",
        ".exe", ".hlp", ".hta", ".inf",
        ".jar", ".jnl", ".jnt", ".js",
        ".jse", ".lnk", ".mht", ".mhtml",
        ".msh", ".msh1", ".msh1xml", ".msh2",
        ".msh2xml", ".msi", ".msp", ".ocx",
        ".pif", ".ps1", ".ps1xml", ".ps2",
        ".ps2xml", ".psc1", ".psc2", ".pub",
        ".reg", ".scf", ".scr", ".url", ".vb",
        ".vbe", ".vbs", ".ws", ".wsc",
        ".wsf", ".wsh"]

RE_EXTS = Regexp.new('('+ EXTS.join('|') + ')$')

PROXY_ERC = 'http://proxysrv.eurocontrol.fr:8080'

class Ctx
  attr_accessor :paths
  attr_accessor :urls
  attr_reader :username
  attr_reader :password
  attr_reader :domain

  attr_accessor :opt_p
  attr_accessor :opt_u

  def initialize
    @paths = []
    @urls = []
    @opt_p = false
    @opt_u = false

    get_password
  end

  def get_password
    begin
      dbrc = DBI::DBRC.new('cimbl')
      @domain = 'SKY'
      @username = dbrc.user
      @password = dbrc.password
      $stderr.puts("Username/password loaded.")
    rescue
      $stderr.puts("No user/pass configured.")
    end
  end
end

def init
end

# Check filename format
#
def right_name?(name)
  name =~ %r{CIMBL-\d+-CERTS\.csv}
end

# Process each filename
def process_path(path)

  # Remove the signature
  #
  file  = path.split('|')[0]

  # These exts are already blocked
  #
  return nil if RE_EXTS.match(file)

  file
end

def blocked_url?(ctx, url)
  begin
    c = HTTPClient.new(:proxy => PROXY_ERC,
                       :timeout => 5,
                       :agent_name => "git/#{ID}")
    c.set_proxy_auth(ctx.username, ctx.password)
    resp = c.head(url,  :follow_redirect => true)
    if resp.status == 302
      "REDIRECT: %s" % resp.headers['Location']
    elsif resp.status == 403
      'BLOCKED-EEC'
    elsif resp.status == 407
      'AUTH'
    else
     '**BLOCK**'
    end
  rescue => err
    $stderr.puts("Error on #{url}: #{err}")
    nil
  end

end

def process_url(ctx, url)
  if url !~ %r{^http}
    url = 'http://' + url
  end
  $stderr.print("URL: #{url}:")
  ret = blocked_url?(ctx, url)
  if ret.nil?
    $stderr.puts('UNKNOWN')
  elsif ret == 'BLOCKED-EEC'
    $stderr.puts(ret)
    return nil
  elsif ret == '**BLOCK**'
    $stderr.puts(ret)
    return url
  end
  nil
end

def analyse_entries(ctx, name)
  cnt = 0
  paths = []
  urls = []
  CSV.foreach(name) do |e|
    cnt += 1
    if (e[2] =~ %r{^filename\|} && ctx.opt_p == false)
      paths << process_path(e[5])
    elsif (e[2] == 'url' && ctx.opt_u == false)
      urls << process_url(ctx, e[5])
    end
  end
  ctx.urls = urls.uniq.compact
  ctx.paths = paths.uniq.compact

  cnt
end


def gen_mail_paths(paths)
  if paths.length != 0
    list = paths.join("\n")
    str = <<-"EOTEXT"
Can you open a ticket to add these filenames to the BLOCKED list?

#{list}
EOTEXT
  str
  else
    ''
  end
end


def gen_mail_urls(urls)
  if urls.length != 0
    list = urls.join("\n")
    str = <<"EOTEXT"
Can you open a ticket to add these URLs to the BLOCKED list on BlueCoat?

#{list}
EOTEXT
  str
  else
    ''
  end
end

def gen_mail(ctx)
  body = <<-"EOTEXT"

Dear Service Desk,
  
#{gen_mail_paths(ctx.paths)}

#{gen_mail_urls(ctx.urls)}
Best regards,
Your friendly script — #{MYNAME}/#{ID}
  EOTEXT
  body
end

def main(argv)
  # Filter on filename
  #
  ctx = Ctx.new

  # CLI options
  #
  GetText.set_locale('En_US.UTF-8')

  usage = <<-"EOTEXT"
Usage: #{MYNAME} [-PU] FILE
  EOTEXT

  banner = <<-"EOTEXT"
#{MYNAME}
Revision #{ID}

#{usage}
  EOTEXT

  argv.options do |opts|
    opts.banner = banner
    opts.on('-P', '--omit-paths', 'Do not look for filenames') do
      ctx.opt_p = true
    end
    opts.on('-U', '--omit-urls', 'Do not look for urls') do
      ctx.opt_u = true
    end
    opts.on('-h', 'Help', 'Display this usage') do
      puts banner
      return 0
    end
    opts.parse!
  end

  argv.options = nil
  name = argv.shift

  if name.nil? || name == ''
    $stderr.puts("You must specify a file.")
    exit 255
  end

  if right_name?(name)
    $stderr.puts("Reading #{name}")
    $stderr.printf("Using proxy %s\n", PROXY_ERC)

    # Read everything
    #
    cnt = analyse_entries(ctx, name)

    # Now act
    #
    urls = ctx.urls
    paths = ctx.paths

    puts(urls)
    puts "======"
    puts(paths)

    printf("%d lines read, %d urls, %d filepaths\n", cnt,
           urls.length,
           paths.length)
  else
    $stderr.printf("Wrong filename %s", name)
    exit 1
  end

  # Generate a mail with info
  #
  if paths.length != 0 || urls.length != 0
    str = gen_mail(ctx)
    puts(str)
  else
    # Or not
    #
    puts "Nothing new"
  end
end

if $0 == __FILE__
  exit(main(ARGV) || 1)
end
