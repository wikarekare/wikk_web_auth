#!/usr/local/bin/ruby
require 'cgi'
require 'json'
require 'wikk_configuration'
require_relative '../lib/wikk_web_auth.rb'

# Fake CGI class, as we aren't actually coming from the web
class Minimal_CGI
  attr_accessor :cookies
  attr_accessor :output_cookies
  attr_accessor :remote_addr
  attr_accessor :output_hidden

  class Cookie < CGI::Cookie
    def initialize(*args)
      super(*args)
      p args
    end
  end

  def initialize(env:)
    @env = env
    @cookies = {}
    @remote_addr = @env['HTTP_X_FORWARDED_FOR'].nil? ? @env['REMOTE_ADDR'] : @env['HTTP_X_FORWARDED_FOR']
    cookie_string = env['HTTP_COOKIE']
    unless cookie_string.nil?
      @key_values = cookie_string.split(';')
      @key_values.each do |kv|
        t = kv.strip.split('=', 2) # Split on first =
        @cookies[t[0]] = t[1] unless t.nil? || t.length != 2
      end
    end
    @output_cookies = []  # We get this back from CGI::Session as an Array of GCI::Cookie entries
    @output_hidden = {}   # We get this back from CGI::Session as a Hash, with the cookie name as the key and session_id as the value
  end

  # return the cgi parameter
  # We aren't passing cgi parameters, so this will always be nil
  def [](_the_key)
    nil
  end

  # Look to see if we have a cgi parameter for this key
  # We aren't passing cgi parameters, so this will always be false
  def key?(_the_key)
    false
  end

  # Convert each cookie to a string, and return the resulting array
  def cookies_to_a
    @output_cookies.map(& :to_s)
  end
end

env = {
  'REMOTE_ADDR' => '127.0.0.1',
  'HTTP_COOKIE' => ''
}
return_url = 'https://127.0.0.1/'

pstore_conf = JSON.parse(File.read(__dir__ + '/conf/pstore.json'))
cgi = Minimal_CGI.new(env: env)
pwd_conf = WIKK::Configuration.new(__dir__ + '/conf/passwd.json')
user_conf = WIKK::Configuration.new(__dir__ + '/conf/test_user.json')

web_auth = WIKK::Web_Auth.new(cgi, pwd_conf, return_url, user: user_conf.user, pstore_config: pstore_conf, run_auth: false)
puts "user: #{web_auth.user}"
puts "Session_id: #{web_auth.session_id}"
puts "Session: #{web_auth.session_to_s}" # Will be nil, if we haven't had a test for a while
puts "Cookies: #{cgi.output_cookies}"
puts "output_hidden: #{cgi.output_hidden}"

puts
puts 'Generating the challenge creates a new session, hence a cookie'
challenge = web_auth.gen_challenge
puts "Challenge: #{challenge}"
puts "Session_id: #{web_auth.session_id}"
puts "Session: #{web_auth.session_to_s}"
puts "Cookies: #{cgi.output_cookies}"
puts "output_hidden: #{cgi.output_hidden}"

puts
puts 'Test that the password is accepted'
# Inject the session cookie
cgi.cookies['_wikk_rb_sess_id'] = web_auth.session_id
# Inject the sha256 response
web_auth.response = Digest::SHA256.digest(user_conf.password + challenge).unpack1('H*')
puts "Authorized? #{web_auth.valid_response?}"
