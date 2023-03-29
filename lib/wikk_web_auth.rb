module WIKK
  require 'cgi'
  require 'cgi/session'
  require 'cgi/session/pstore'     # provides CGI::Session::PStore
  require 'digest/sha2'
  require 'syslog/logger'
  require 'wikk_aes_256'
  require 'wikk_password'

  # Provides common authentication mechanism for all our cgis.
  #  @attr_reader [String] user , the remote user's user name
  #  @attr_reader [String] session , the persistent Session record for this user
  class Web_Auth
    VERSION = '0.1.5' # Gem version

    attr_reader :user, :session

    # Create new Web_Auth instance, and proceed through authentication process by creating a login web form, if the user isn't authenticated.
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    #  @param pwd_config [WIKK::Configuration|Hash] the location of the password file is embedded here.
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @param return_url [String] If we successfully authenticate, return here.
    #  @return [WIKK::Web_Auth]
    def initialize(cgi, pwd_config = nil, return_url = nil, pstore_config: nil)
      if pwd_config.instance_of?(Hash)
        sym = pwd_config.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
        @config = Struct.new(*(k = sym.keys)).new(*sym.values_at(*k))
      else
        @pwd_config = pwd_config
      end

      @cgi = cgi
      @pstore_config = pstore_config
      @user = ''
      @session = nil
      begin
        @log = Syslog::Logger.syslog
      rescue StandardError
        @log = Syslog::Logger.new('wikk_web_auth')
      end
      authenticate(return_url)
    end

    # way of checking without doing a full login sequence.
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @return [Boolean] authenticated == true.
    def self.authenticated?(cgi, pstore_config: nil )
      begin
        session = CGI::Session.new(cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: pstore_config ) )
        authenticated = (session != nil && session['session_expires'] > Time.now && session['auth'] == true && session['ip'] == cgi.remote_addr)
        session.close # Writes back the session data
        return authenticated
      rescue ArgumentError => e # if no old session to find.
        begin
          @log = Syslog::Logger.syslog
        rescue StandardError
          @log = Syslog::Logger.new('wikk_web_auth')
        end
        @log.error(e.message)
        return false
      end
    end

    # get the session reference and delete the session.
    #  @param pstore_config [Hash] overrides default pstore settings
    #  @param cgi [CGI] Which carries the client data, cookies, and PUT/POST form data.
    def self.logout(cgi, pstore_config: nil)
      begin
        session = CGI::Session.new(cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: pstore_config ))
        session.delete if session != nil
      rescue ArgumentError => e # if no old session
        begin
          @log = Syslog::Logger.syslog
        rescue StandardError
          @log = Syslog::Logger.new('wikk_web_auth')
        end
        @log.error(e.message)
      end
    end

    # Checks password file to see if the response from the user matches generating a hash from the password locally.
    #  @param user [String] Who the remote user claims to be
    #  @param challenge [String] Random string we sent to this user, and they used in hashing their password.
    #  @param received_hash [String] The hex_SHA256(password + challenge) string that the user sent back.
    #  @return [Boolean] True for authorization test suceeded.
    def authorized?(user, challenge, received_hash)
      begin
        return WIKK::Password.valid_sha256_response?(user, @pwd_config, challenge, received_hash)
      rescue IndexError => e # User didn't exist
        @log.error("authorized?(#{user}) User not found: " + e.message)
        return false
      rescue Exception => e # rubocop:disable Lint/RescueException  # In a cgi, we want to log all errors.
        @log.error("authorized?(#{user}): " + e.message)
        return false
      end
    end

    # Generate the new Session's config parameters, mixing in and/or overriding the preset values.
    #  @param pstore_config [Hash] Override the default pstore configurations. Only changed keys need to be included
    #  @param extra_arguments [Hash] Extra arguments that get added to the hash. Will also override values with the same key.
    #  @return [Hash] The configuration hash.
    def self.session_config( extra_arguments = nil, pstore_config: nil )
      instance_of?(Hash)
      session_conf = {
        'database_manager' => CGI::Session::PStore,  # use PStore
        'session_key' => '_wikk_rb_sess_id',                # custom session key
        'session_expires' => (Time.now + 86400),   # 1 day timeout
        'prefix' => 'pstore_sid_',                          # Prefix for pstore file
        'tmpdir' => '/tmp',                          # PStore option. Under Apache2, this is a private namespace /tmp
        'session_path' => '/'               # The cookie gets returned for URLs starting with this path
        # 'session_id' => ?,                         # Created for new sessions. Merged in for existing sessions
        # 'new_session' => true,                     # Default, is to create a new session if it doesn't already exist
        # 'no_hidden' => ?,
        # 'session_domain' => ?,
        # 'session_secure' => ?,
        # 'no_cookies' => ?, #boolean
        # 'suffix' => ?
      }
      session_conf.merge!(pstore_config) if pstore_config.instance_of?(Hash)
      session_conf.merge!(extra_arguments) if extra_arguments.instance_of?(Hash)
      return session_conf
    end

    def session_state_init(session_options = {})
      session_options.each { |k, v| @session[k] = v }
    end

    # Test to see if we are already authenticated, and if not, generate an HTML login page.
    #  @param return_url [String] We return here if we sucessfully login
    def authenticate(return_url = nil)
      begin
        @session = CGI::Session.new(@cgi, Web_Auth.session_config( { 'new_session' => false }, pstore_config: @pstore_config )) # Look for existing session.
        return gen_html_login_page(return_url) if @session.nil?
      rescue ArgumentError => _e # if no old session
        return gen_html_login_page(return_url)
      rescue Exception => e # rubocop:disable Lint/RescueException In CGI, we want to handle every exception
        @log.error("authenticate(#{@session}):  #{e.message}")
        raise e.class, 'Authenticate, CGI::Session.new ' + e.message
      end

      begin
        @session['auth'] = false if @session['session_expires'].nil? ||
                                    @session['session_expires'] < Time.now || # Session has expired
                                    @session['ip'] != @cgi.remote_addr || # Not coming from same IP address
                                    CGI.escapeHTML(@cgi['logout']) != '' # Are trying to logout

        return if @session['auth'] == true # if this is true, then we have already authenticated this session.

        if (challenge = @session['seed']) != '' # see if we are looking at a login response.
          @user = CGI.escapeHTML(@cgi['Username'])
          response = CGI.escapeHTML(@cgi['Response'])
          if @user != '' && response != '' && authorized?(@user, challenge, response)
            @session['auth'] = true # Response valid.
            @session['user'] = @user
            @session['ip'] = @cgi.remote_addr
            @session['seed'] = '' # Don't use the same one twice.
            @session.close
            return
          end
        end

        @session.delete # Start a new session.
        gen_html_login_page(return_url)
        @session.close if @session != nil # Saves the session state.
      rescue Exception => e # rubocop:disable Lint/RescueException
        @log.error("authenticate(#{@session}):  #{e.message}")
        raise e.class, 'Authenticate, CGI::Session.new ' + e.message
      end
    end

    # clean up the session, setting @authenticated to false and deleting the session state.
    def logout
      @session.delete if @session != nil
    end

    # Test to see if user authenticated,
    #  @return [Boolean] i.e @authenticated's value.
    def authenticated?
      @session != nil && @session['session_expires'] > Time.now && @session['auth'] == true && session['ip'] == @cgi.remote_addr
    end

    # Used by calling cgi to generate a standard login page
    #  @param return_url [String] We return here if we sucessfully login
    def gen_html_login_page(return_url = nil)
      session_options = Web_Auth.session_config( pstore_config: @pstore_config )
      @session = CGI::Session.new(@cgi, session_options ) # Start a new session for future authentications.

      raise 'gen_html_login_page: @session == nil' if @session.nil?

      challenge = WIKK::AES_256.gen_key_to_s
      session_state_init('auth' => false, 'seed' => challenge, 'ip' => @cgi.remote_addr, 'session_expires' => session_options['session_expires'])
      @cgi.header('type' => 'text/html')
      @cgi.out do
        @cgi.html do
          @cgi.head { @cgi.title { 'login' } + html_nocache + html_script } +
            @cgi.body { html_login_form(user, challenge, return_url) + "\n" }
        end
      end
      @session.update
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
    #  @param return_url [String] Pass the url we want to return to if the login succeeds.
    #  @return [String] Login form to embed in html response to user.
    private def html_login_form(user, challenge, return_url = '')
      <<~HTML
        <form NAME="login" ACTION="/ruby/login.rbx" METHOD="post">
        <input TYPE="hidden" NAME="Challenge" VALUE="#{challenge}">
        <input TYPE="hidden" NAME="Response" VALUE="">
        <input TYPE="hidden" NAME="ReturnURL" VALUE="#{return_url}">
        <table>
        <tr><th>User name</th><td><input TYPE="text" NAME="Username" VALUE="#{user}" SIZE="32" MAXLENGTH="32"></td></tr>
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
