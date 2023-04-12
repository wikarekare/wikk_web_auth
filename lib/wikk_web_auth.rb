module WIKK
  require 'cgi'
  require 'cgi/session'
  require 'cgi/session/pstore'     # provides CGI::Session::PStore
  require 'digest/sha2'
  require 'syslog/logger'
  require 'wikk_aes_256'
  require 'wikk_password'

  # Provides common authentication mechanism for all our cgis.
  # Uses standard cgi parameters, unless overridden e.g. cgi?user=x&response=y
  # Returns values imbedded as hidden fields in the login form
  #  @attr_reader [String] user , the remote user's user name
  #  @attr_reader [String] session , the persistent Session record for this user
  class Web_Auth
    VERSION = '0.1.6' # Gem version

    attr_reader :user, :challenge
    attr_accessor :response

    # Create new Web_Auth instance, and proceed through authentication process by creating a login web form, if the user isn't authenticated.
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    #  @param pwd_config [WIKK::Configuration|Hash] the location of the password file is embedded here.
    #  @param user [String] overrides cgi['user']
    #  @param response [String] overrides cgi['response']
    #  @param user_logout [Boolean] overrides cgi['logout']
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @param return_url [String] If we successfully authenticate, return here.
    #  @return [WIKK::Web_Auth]
    def initialize(cgi, pwd_config = nil, return_url = nil, user: nil, response: nil, user_logout: false, pstore_config: nil, run_auth: true)
      if pwd_config.instance_of?(Hash)
        sym = pwd_config.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
        @config = Struct.new(*(k = sym.keys)).new(*sym.values_at(*k))
      else
        @pwd_config = pwd_config
      end

      begin
        @log = Syslog::Logger.syslog
      rescue StandardError
        @log = Syslog::Logger.new('wikk_web_auth')
      end

      @cgi = cgi
      @pstore_config = pstore_config

      # Set variables from the method's params, or alternately, from the CGI params
      @user = user.nil? ? cgi_param(@cgi['Username']) : user
      @response = response.nil? ? cgi_param(@cgi['Response']) : response
      @return_url = return_url.nil? ? cgi_param(@cgi['ReturnURL']) : return_url

      # Look for existing session, but don't start a new one.
      begin
        @session = CGI::Session.new(@cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: @pstore_config ))
      rescue ArgumentError => _e # if no old session
        @session = nil
      rescue Exception => e # rubocop:disable Lint/RescueException In CGI, we want to handle every exception
        @log.log(Syslog::LOG_NOTICE, "authenticate(#{@session}):  #{e.message}")
        raise e.class, 'Authenticate, CGI::Session.new ' + e.message
      end

      if @session.nil?
        @challenge = '' # there is no current challenge
      elsif @session['session_expires'].nil? ||       # Shouldn't be the case
            @session['session_expires'] < Time.now || # Session has expired
            @session['ip'] != @cgi.remote_addr ||     # Not coming from same IP address
            @session['user'] != @user ||              # Not the same user
            cgi_param(@cgi['logout']) != '' ||        # Requested a logout
            user_logout                               # Alternate way to request a logout
        logout
      else
        # We ignore the cgi['Challenge'] value, and always get this from the pstore
        @challenge = @session['seed'] # Recover the challenge from the pstore entry. It may be ''
      end

      authenticate if run_auth # This generates html output, so it is now conditionally run.
    end

    # Debug dump of session keys
    def session_to_s
      return '' if @session.nil?

      s = '{'
      [ 'auth', 'seed', 'ip', 'user', 'session_expires' ].each do |k|
        s += "'#{k}':'#{@session[k]}', "
      end
      s += '}'
      return s
    end

    # expose the session_id. This is also returned by modifying the cgi instance passed in to initialize
    # * The cgi.output_cookies Array of Cookies gets modified if no_cookies is false (the default)
    # * And cgi.output_hidden Hash get modified if no_hidden is false (the default)
    # @return [String] random session id
    def session_id
      @session.nil? ? '' : @session.session_id
    end

    # way of checking without doing a full login sequence.
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @return [Boolean] authenticated == true.
    def self.authenticated?(cgi, pstore_config: nil )
      begin
        session = CGI::Session.new(cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: pstore_config ) )
        authenticated = (session != nil && !session['session_expires'].nil? && session['session_expires'] > Time.now && session['auth'] == true && session['ip'] == cgi.remote_addr)
        session.close # Tidy up, so we don't leak file descriptors
        return authenticated
      rescue ArgumentError => e # if no old session to find.
        begin
          @log = Syslog::Logger.syslog
        rescue StandardError
          @log = Syslog::Logger.new('wikk_web_auth')
        end
        @log.log(Syslog::LOG_NOTICE, e.message)
        return false
      end
    end

    # Test to see if user authenticated.
    # If this is the only call, then follow this with close_session()
    #  @return [Boolean] True, if this session is authenticated
    def authenticated?
      @session != nil && !@session['session_expires'].nil? && @session['session_expires'] > Time.now && @session['auth'] == true && @session['ip'] == @cgi.remote_addr
    end

    # get the session reference and delete the session.
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    def self.logout(cgi, pstore_config: nil)
      begin
        session = CGI::Session.new(cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: pstore_config ))
        session.delete unless session.nil? # Also closes the session
      rescue ArgumentError => e # if no old session
        begin
          @log = Syslog::Logger.syslog
        rescue StandardError
          @log = Syslog::Logger.new('wikk_web_auth')
        end
        @log.log(Syslog::LOG_NOTICE, e.message)
      end
    end

    # clean up the session, deleting the session state.
    def logout
      @session.delete unless @session.nil? # Will close the existing session
      @session = nil
      @challenge = '' # no current session, so no challenge string
    end

    # Generate the new Session's config parameters, mixing in and/or overriding the preset values.
    #  @param pstore_config [Hash] Override the default pstore configurations. Only changed keys need to be included
    #  @param extra_arguments [Hash] Extra arguments that get added to the hash. Will also override values with the same key.
    #  @return [Hash] The configuration hash.
    def self.session_config( extra_arguments = nil, pstore_config: nil )
      instance_of?(Hash)
      session_conf = {
        'database_manager' => CGI::Session::PStore,  # use PStore
        'session_key' => '_wikk_rb_sess_id',         # custom session key
        'session_expires' => (Time.now + 86400),     # 1 day timeout
        'prefix' => 'pstore_sid_',                   # Prefix for pstore file
        # 'suffix' => ?
        'tmpdir' => '/tmp',                          # PStore option. Under Apache2, this is a private namespace /tmp
        'session_path' => '/',                       # The cookie gets returned for URLs starting with this path
        # 'new_session' => true,                     # Default, is to create a new session if it doesn't already exist
        # 'session_domain' => ?,
        # 'session_secure' => ?,
        # 'session_id' => ?,                         # Created for new sessions. Merged in for existing sessions
        'no_cookies' => false,                       # boolean. Do fill in cgi output_cookies array of Cookies
        'no_hidden' => false                         # boolean fill in the cgi output_hidden Hash key=cookie, value=session_id
      }
      session_conf.merge!(pstore_config) if pstore_config.instance_of?(Hash)
      session_conf.merge!(extra_arguments) if extra_arguments.instance_of?(Hash)
      return session_conf
    end

    # Generate a challenge, as step 1 of a login
    # If this is the only call, then follow this with close_session()
    def gen_challenge
      @session.delete unless @session.nil? # Closes and Deletes the existing session
      # Start a new session for future authentications.
      # This resets the expiry timestamp
      session_options = Web_Auth.session_config( pstore_config: @pstore_config )
      @session = CGI::Session.new(@cgi, session_options )

      raise 'gen_challenge: @session == nil' if @session.nil?

      @challenge = WIKK::AES_256.gen_key_to_s
      # Store the challenge in the pstore, ready for the 2nd login step, along with browser details
      session_state_init('auth' => false, 'seed' => @challenge, 'ip' => @cgi.remote_addr, 'user' => @user, 'session_expires' => session_options['session_expires'])
      @session.update
      return @challenge
    end

    # Test the response against the password file
    # If this is the only call, then follow this with close_session()
    # @return [Boolean] We got authorized
    def valid_response?
      if @session.nil? || @challenge == '' # Double check that we aren't getting packets out of order
        # We didn't store a challenge string, so we shouldn't be here yet
        return false
      elsif @user != '' && @response != '' && authorized?
        # We got a challenge string, so we are on step 2 of the authentication
        # And have passed the password check ( authorized?() )
        @session['auth'] = true # Response valid.
        @challenge = @session['seed'] = '' # Don't use the same challenge twice, so next call will look like a fresh login.
        @session.update       # Should also update on close, which we probably do next
        return true
      else # Failed to authorize
        @challenge = @session['seed'] = '' # Don't use the same challenge twice, so next call will look like a fresh login.
        @session.update       # Should also update on close, which we probably do next
        return false
      end
    end

    # Test to see if we are already authenticated, and if not, generate an HTML login page.
    #  @param return_url [String] We return here if we sucessfully login. Overrides initialize value
    def authenticate(return_url = nil)
      @return_url = return_url unless return_url.nil? # Update the return url (Backward compatibility)
      # We have no session setup, or haven't sent the challenge.
      if @session.nil? || @challenge == ''
        gen_html_login_page
        return
      end

      begin
        # Might be a while since we initialized the class, so repeat this test
        @session['auth'] = false if @session['session_expires'].nil? ||       # Shouldn't ever happen, but has
                                    @session['session_expires'] < Time.now || # Session has expired
                                    @session['ip'] != @cgi.remote_addr ||     # Not coming from same IP address
                                    @session['user'] != @user                 # Username not the same as the session

        return if @session['auth'] == true # if this is true, then we have already authenticated this session.

        # We should be in step 2, expecting a response to the challenge
        unless valid_response?
          gen_html_login_page
        end
        @session.close unless @session.nil? # Saves the session state.
      rescue Exception => e # rubocop:disable Lint/RescueException
        @log.log(Syslog::LOG_NOTICE, "authenticate(#{@session}):  #{e.message}")
        raise e.class, 'Authenticate, CGI::Session.new ' + e.message
      end
    end

    # Ensure we don't consume all file descriptors
    # Call after last call (though most calls do close the session)
    def close_session
      @session.close unless @session.nil?
      @session = nil
    end

    # Used by calling cgi to generate a standard login page
    def gen_html_login_page
      gen_challenge
      @cgi.header('type' => 'text/html')
      @cgi.out do
        @cgi.html do
          @cgi.head { @cgi.title { 'login' } + html_nocache + html_script } +
            @cgi.body { html_login_form + "\n" }
        end
      end
    end

    # Used by calling cgi to inject a return URL into the html response.
    # Called by calling cgi, when constructing their html headers.
    #  @param url [String] URL to redirect to.
    #  @return [String] The HTML meta header, or "", if url is empty.
    def html_reload(url = nil)
      if url != nil && url != ''
        "<meta http-equiv=\"Refresh\" content=\"0; URL=#{url}\">\n"
      else
        ''
      end
    end

    # Used by calling cgi to generate logout with this form.
    #  @param cgi_dir [String] directory holding the login.rbx cgi.
    #  @return [String] Html logout form.
    def html_logout_form(cgi_dir)
      <<~HTML
        <form NAME="login" ACTION="#{cgi_dir}/login.rbx" METHOD="post">
        <input TYPE="submit" NAME="logout" VALUE="logout" >
        </form>
      HTML
    end

    # Get a CGI param
    # @param key [String] name of the CGI param
    # @return [String] Either the value, or ''
    private def cgi_param(key)
      value = @cgi[key]
      return value.nil? ? '' : CGI.escapeHTML(value)
    end

    # Short hand for set up of the pstore session entry
    # @param session_options [Hash] key pairs for the pstore session
    private def session_state_init(session_options = {})
      session_options.each { |k, v| @session[k] = v }
    end

    # Checks password file to see if the response from the user matches generating a hash from the password locally.
    #  @param user [String] Who the remote user claims to be
    #  @param challenge [String] Random string we sent to this user, and they used in hashing their password.
    #  @param response [String] The hex_SHA256(password + challenge) string that the user sent back.
    #  @return [Boolean] True for authorization test suceeded.
    private def authorized?
      begin
        return false if @challenge.nil? || @challenge == ''

        return WIKK::Password.valid_sha256_response?(@user, @pwd_config, @challenge, @response)
      rescue IndexError => e # User didn't exist
        @log.log(Syslog::LOG_NOTICE, "authorized?(#{@user}) User not found: " + e.message)
        return false
      rescue Exception => e # rubocop:disable Lint/RescueException  # In a cgi, we want to log all errors.
        @log.log(Syslog::LOG_NOTICE, "authorized?(#{@user}): " + e.message)
        return false
      end
    end

    # Login form javascript helper to SHA256 Hash a password and the challenge string sent by the server.
    #  @return [String] Javascript to embed in html response.
    private def html_script
      <<~HTML
        <script type="text/javascript" src="/js/sha256.js"></script>

        <script language="JavaScript">
        function sendhash() {
            str = document.login.Password.value +
                document.login.Challenge.value;

            document.login.Response.value = hex_sha256(str);
            document.login.Password.value = "";
            document.login.Challenge.value = "";
            document.login.submit();
        }
        </script>
      HTML
    end

    # Generate html login form.
    #  @param user [String] user's login name.
    #  @param challenge [String] Random bytes to add to password, before sending back to server.
    #  @param return_url [String] We return here if we sucessfully login. Overrides initialize value
    #  @return [String] Login form to embed in html response to user.
    private def html_login_form
      <<~HTML
        <form NAME="login" ACTION="/ruby/login.rbx" METHOD="post">
        <input TYPE="hidden" NAME="Challenge" VALUE="#{@challenge}">
        <input TYPE="hidden" NAME="Response" VALUE="">
        <input TYPE="hidden" NAME="ReturnURL" VALUE="#{@return_url}">
        <table>
        <tr><th>User name</th><td><input TYPE="text" NAME="Username" VALUE="#{@user}" SIZE="32" MAXLENGTH="32"></td></tr>
        <tr><th>Password</th><td><input TYPE="password" NAME="Password" VALUE="" SIZE="32" MAXLENGTH="32"></td></tr>
        <tr><td>&nbsp;</td><td>
          <input ONCLICK="sendhash(); return false;" TYPE="submit" NAME="login" VALUE="Login">
          <input TYPE="button" NAME="Cancel" VALUE="   Cancel   "
          ONCLICK="document.login.Username.value='';document.login.Password.value=';return false;'">
        </td></tr>
        </table>
        </form>
        <script LANGUAGE="javascript" TYPE="text/javascript">
              document.login.Username.focus();
        </script>
      HTML
    end

    # Generate no cache metadata header record.
    #  @return [String] Html no-cache meta tag
    private def html_nocache
      '<META HTTP-EQUIV="Pragma" CONTENT="no-cache">'
    end
  end
end
