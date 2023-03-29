require 'cgi'
require_relative '../lib/wikk_web_auth.rb'
require 'wikk_configuration'
require 'pp'

web_text_1 = <<~HTML
  POST /ruby/login.rbx HTTP/1.1
  Host: admin2.wikarekare.org
  User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0) Gecko/20100101 Firefox/31.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: en-gb,en;q=0.5
  Accept-Encoding: gzip, deflate
  DNT: 1
  Referer: http://admin2.wikarekare.org/ruby/login.rbx
  Connection: keep-alive
HTML

$stdin = StringIO.new web_text_1
cgi = CGI.new('html5')

@authenticated = WIKK::Web_Auth.authenticated?(cgi)
puts @authenticated

conf = WIKK::Configuration.new(__dir__ + 'passwd.json')
return_url = 'http://www.wikarekare.org'

auth = WIKK::Web_Auth.new(cgi, conf, return_url)

# If we are authenticated, then decide if we want a fast return,
# Or offer a logout.

if auth.authenticated?
  if action == 'logout'
    auth.logout
  end
  cgi.header('type' => 'text/html')
  cgi.out do
    cgi.html do
      cgi.head { cgi.title { 'login' } + auth.html_reload(return_url) } +
        cgi.body do
          if auth.authenticated?
            "Welcome #{auth.user}<br>\n" +
              auth.html_logout_form
          else
            ''
          end
        end
    end
  end
end
