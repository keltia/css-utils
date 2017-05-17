#! /usr/bin/env ruby
#
# @author Ollivier Robert <ollivier.robert@eurocontrol.int>
# @copyright © 2017 by Ollivier Robert for DG/CSS
#

require 'csv'
require 'httpclient'
require 'dbi/dbrc'

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

  def initialize
    @paths = []
    @urls = []
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
  file, sig = path.split('|')

  # These exts are already blocked
  #
  return nil if RE_EXTS.match(file)

  file
end

def blocked_url?(ctx, url)
  begin
    c = HTTPClient.new(:proxy => PROXY_ERC,
                       :timeout => 5,
                       :agent_name => 'git/0.0.0-eec')
    c.set_proxy_auth(ctx.username, ctx.password)
    resp = c.head(url)
    if resp.status == 200
      '**BLOCK**'
    elsif resp.status == 302
      "REDIRECT: %s" % resp.headers['Location']
    elsif resp.status == 403
      'BLOCKED-EEC'
    elsif resp.status == 407
      'AUTH'
    else
      nil
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
  print("URL: #{url}:")
  ret = blocked_url?(ctx, url)
  if ret.nil?
    puts('UNKNOWN')
  elsif
    puts(ret)
  end
end

def analyse_entries(ctx, name)
  cnt = 0
  paths = []
  urls = []
  CSV.foreach(name) do |e|
    cnt += 1
    if e[2] =~ %r{^filename\|}
      paths << process_path(e[5])
    elsif e[2] == 'url'
      urls << process_url(ctx, e[5])
    end
  end
  ctx.urls = urls.compact.uniq
  ctx.paths = paths.compact.uniq

  cnt
end


def gen_mail_paths(paths)
  if paths.length != 0
    list = paths.collect {|p| p + "\n"}.join("\n")
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
    list = urls.collect {|u| u + "\n"}.join("\n")
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
  EOTEXT
  body
end

def main(argv)
  # Filter on filename
  #
  ctx = Ctx.new



  name = argv[0]
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
