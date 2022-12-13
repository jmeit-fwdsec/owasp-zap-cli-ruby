require "#{__dir__}/owasp_zap_ruby"
require 'json'
require 'fileutils'
require 'open3'
require 'concurrent'
require "#{__dir__}/progressbar"
require 'rexml/document'
include REXML

class ZapScan

  def initialize(
    zap_bin: '/zap/zap.sh',
    zap_host: '127.0.0.1', # Using 'localhost' can sometimes default to ipv6, which doesn't work with Zap.
    zap_port: '8080',
    zap_api_key: '123456789',
    zap_home_dir: '/home/repo/eureka/run/zap',
    zap_api_defs: "#{__dir__}/zap-api.json",
    output_dir: __dir__,
    api_files_dir: '/home/repo/zap/swagger',
    api_files_type: 'openapi',
    policy_file: '/home/repo/zap/zap.policy',
    context_file: '/home/repo/zap/zap.context',
    addons: [],
    skip_auth: false,
    auth_token_duration: 300,
    auth_script_file: '/home/repo/zap/auth.sh',
    auth_headers: [{'header'=>'Authorization','value_prefix'=>'Bearer '}],
    report_html: false
  )

    # project config
    @policy_file = policy_file
    @policy_name = get_name_from_xml policy_file, 'policy'
    @context_file = context_file
    @context_name = get_name_from_xml context_file, 'context'

    # Authentication config
    @skip_auth = skip_auth
    @auth_token_duration = auth_token_duration
    @auth_script_file = auth_script_file
    @auth_headers = auth_headers

    # API files for openapi/swagger or postman
    @api_files_dir = api_files_dir
    allowed_api_types = {
      openapi: "openapi",
      swagger: "openapi",
      postman: "postman",
      graphql: "graphql"
    }
    # Validate that argument api_files_type is in allowed_api_types
    @api_files_type = allowed_api_types[ api_files_type.downcase.to_sym ].nil? ? 'openapi' : allowed_api_types[ api_files_type.downcase.to_sym ]


    # Export Report files Locations
    @output_dir = output_dir
    @report_html = report_html

    # ZAP config
    @zap_bin = zap_bin
    @zap_port = zap_port
    @zap_api_key = zap_api_key
    @zap_host = zap_host
    @zap_api_defs = zap_api_defs
    @addons = addons

    @zap_home_dir = File.expand_path( zap_home_dir )
    @auth_token_loop_thread = nil
    @findings = 0

  end


  def move_files_to_zap_home

    # Zap can't read files outside of it's home directory.
    # So we copy all files there.

    files = {
      'contexts'=> @context_file, 
      'policies'=> @policy_file
    }
    files.each do |dir,file|
      FileUtils.mkdir_p( "#{@zap_home_dir}/#{dir}" ) unless Dir.exist?( "#{@zap_home_dir}/#{dir}" )
      FileUtils.copy_file( file, "#{@zap_home_dir}/#{dir}/#{File.basename(file)}" ) if File.exist?( file )
    end
    
    dirs = [
      @api_files_dir
    ]
    dirs.each do |d|
      begin
        FileUtils.cp_r( d, @zap_home_dir )
      rescue => e
        raise e
      end
    end
  end


  def import_api_files(zap, api_url)
    
    api_files = Dir.glob( "#{@zap_home_dir}/#{File.basename(@api_files_dir)}/**/*.{json,yaml,yml,graphql,schema}" )
    
    if @api_files_type == 'postman'
      import_postman( zap, api_url, api_files )
    elsif @api_files_type == 'openapi'
      import_openapi( zap, api_url, api_files )
    elsif @api_files_type == 'graphql'
      import_graphql( zap, api_url, api_files )
    end

    puts 'Done.'

  end


  def import_postman(zap, api_url, api_files)

    puts 'Importing Postman collections'

    file_identifier_keys = {
      "_postman_variable_scope": "environment",
      "item": "collection"
    }
    postman_files = {}

    api_files.sort.each do |pmf|
      pmf_obj = JSON.parse( File.read( pmf ) )

      file_identifier_keys.each do |idk, idv|
        if pmf_obj.key?( idk.to_s )
          postman_files[ idv.to_sym ] = pmf
          puts "Found #{idv} file"
        end
      end

    end
    
    run_newman( api_url, postman_files[ :collection ], postman_files[ :environment ] )

    puts "Proxying ZAP through Newman"

  end


  def run_newman( api_url, pm_collection, pm_environment )
    
    command = [ "#{URI(api_url).scheme.upcase}_PROXY=http://#{@zap_host}:#{@zap_port} newman run \"#{pm_collection}\" -e \"#{pm_environment}\" --reporters cli --insecure --global-var \"baseUrl=#{api_url}\"" ]

    Open3.popen3(*command) do |stdin, stdout, stderr, wait_thread|
      #Thread.new do
        stdout.each {|l| puts l } # unless suppress.include? 'stdout'
        stderr.each {|l| puts l } # unless suppress.include? 'stderr'
      #end
    
      stdin.close
    end

  end


  def import_openapi(zap, api_url, api_files)

    puts 'Importing OpenAPI/Swagger definitions'

    api_files.sort.each do |oaf|
      zap.openapi_importFile( file: oaf, target: api_url )
      puts "Imported #{oaf}"
    end
    
  end


  def import_graphql(zap, api_url, api_files)

    puts 'Importing GraphQL Schema'

    api_files.sort.each do |gqlf|
      zap.graphql_importUrl( endurl: api_url )
      puts "Imported #{gqlf}"
    end
    
  end


  def get_api_host_url(zap, _ctx_id)
    
    target_host = ENV['TARGET_HOST']
    if not ENV.keys.include? 'TARGET_HOST' or target_host.empty?
      in_scope = zap.context_includeRegexs( contextName: @context_name )['includeRegexs']
      target_host = in_scope[0]
    else
      in_scope = zap.context_includeInContext( regex: target_host, contextName: @context_name )
    end

    puts( "Target Host: #{target_host}" )
    target_host
  end


  def build_context(zap)

    puts 'Building Zap context'

    zap.context_removeContext( contextName: @context_name )
    
    ctx = zap.context_importContext( contextFile: "#{@zap_home_dir}/contexts/#{File.basename(@context_file)}" )
    
    ctx['contextId']

  end


  def setup_auth_token( zap, ctx_id )

    puts '# Fetching new auth token'

    cmds = {
      "py"=> "python3",
      "sh"=> "bash"
    }

    if File.exist?( @auth_script_file )
      valid_filename = /^[a-zA-Z0-9_-]+\.(#{cmds.keys.join('|')})$/
      if not valid_filename.match?( File.basename( @auth_script_file ) )
        return false
      end
      
      auth_script_file_ext = File.extname( @auth_script_file )[1..-1]

      result = Open3.capture3( "#{cmds[auth_script_file_ext]} #{@auth_script_file}" )
      token = result[0].strip

    else
      # Get users in context
      users = zap.users_usersList( contextId: ctx_id )['usersList']
      auth_ctx = zap.authentication_getAuthenticationMethod( contextId: ctx_id )['method']
      
      begin
        token = get_auth_token( auth_ctx['loginUrl'], auth_ctx['loginRequestData'], users[0]['credentials'] )
      rescue => e
        pp e
        raise 'There was a problem fetching the auth token. ZAP scan has been canceled.'
      end
    end

    @auth_headers.each do |hdr|
    
      value_prefix = hdr.key?('value_prefix') ? hdr['value_prefix'] : ''
      value_suffix = hdr.key?('value_suffix') ? hdr['value_suffix'] : ''
      auth = "#{value_prefix}#{token}#{value_suffix}"
      
      zap.replacer_removeRule( description: 'custom_auth' )
      zap.replacer_addRule(
        description: 'custom_auth',
        enabled: true,
        matchType: 'REQ_HEADER',
        matchRegex: true,
        matchString: hdr['header'],
        replacement: auth
      )
    end
    
    puts 'Auth token refreshed'

    return true
  end

  def get_auth_token( login_url, body_format, credentials )

    credentials = JSON.parse(credentials)
    body_format = JSON.generate(body_format)

    %w[username password].each do |k|
      body_format = body_format.gsub( "{%#{k}%}" , credentials[k] )
    end

    auth = JSON.parse(body_format)
    
    res = Net::HTTP.post( URI(login_url), auth.to_json, "Content-Type" => "application/json" )

    unless res.code.to_i == 200
      raise "Server returned #{res.code} trying to fetch auth token."
    end

    body = JSON.parse(res.body)

    begin
      body['Token']
    rescue
      raise 'Failed to get token'
    end

  end


  def build_zap
    
    puts 'Building ZAP...'

    zap = OwaspZapAPI::Zap.new(
      zap_api_key: @zap_api_key,
      zap_host: @zap_host,
      zap_port: @zap_port,
      zap_bin: @zap_bin,
      zap_api_defs: @zap_api_defs
    )
    
    begin
      zap_version = zap.core_version['version']
      puts "OWASP ZAP version found: #{zap_version}"
    rescue => e
      raise e
    end

    @zap_home_dir = zap.core_homeDirectory['homeDirectory'] if @zap_home_dir == ''

    install_addons zap
    
    puts 'Done.'
    
    zap
  end

  
  def install_addons( zap )
    @addons.each do |addon|
      puts "Installing addon: #{addon}"
      zap.autoupdate_installAddon( id: addon )
    end
  end


  def active_scan( zap, ctx_id )

    puts 'Beginning active scan...'

    if File.exist?( @policy_file )
      puts( "Importing Policy: #{@policy_name}" )
      zap.ascan_importScanPolicy( path: "#{@zap_home_dir}/policies/#{File.basename(@policy_file)}" )
    end

    zap.ascan_enableAllScanners( scanPolicyName: @policy_name )
    
    active_scan_id = zap.ascan_scan( contextId: ctx_id, scanPolicyName: @policy_name )

    active_scan_id['scan']

  end


  def progress( zap, scan_id )

    bar = ProgressBar::ProgressBar.new

    while bar.progress < 100 do

      scan_plugins = zap.ascan_scanProgress( scanId: scan_id )['scanProgress']

      if scan_plugins.is_a?(Array) && scan_plugins.length > 1

        scan_plugins = scan_plugins[1]['HostProcess']

        # Set @findings flag if ZAP discovers anything from the active scan
        scan_plugins.each do |sp|
          if !@findings && sp['Plugin'][6].to_i > 0
            @findings = 1
          end

          if sp['Plugin'][3].include?('%')
            bar.meta "<< #{sp['Plugin'][0]} - #{sp['Plugin'][5]} Reqs"
            break
          end
        end

      end

      bar.update zap.ascan_status( scandId: scan_id )['status'].to_f
      sleep 1

    end

    bar.update 100
    bar.meta "Finished"
  end


  def write_reports( zap, output_dir )
  
    puts 'Exporting report(s)'
    
    FileUtils.mkdir_p( 'eureka/reports' )
    timestamp = Time.now.strftime("%s")
    
    if @report_html == true

      # TODO: Add configurable severities and confidences to appear in report. The API offers these as params.
      report_filename = "zap-report-#{timestamp}"
      zap.reports_generate(
        title: "ZAP Scanning Report - Modern",
        template: "modern", #"risk-confidence-html",
        theme: "marketing", #"original",
        reportFileName: "#{report_filename}.html",
        reportDir: @zap_home_dir,
        display: "false"
      )
      # Zap can only write reports to it's home folder. This moves it to the proper output folder.
      FileUtils.move( "#{@zap_home_dir}/#{report_filename}.html", "#{output_dir}/#{report_filename}.html" )
      FileUtils.move( "#{@zap_home_dir}/#{report_filename}", "#{output_dir}/#{report_filename}" )

      report_filename = "zap-risk-report-#{timestamp}"
      zap.reports_generate(
        title: "ZAP Scanning Report - Risk-Confidence",
        template: "risk-confidence-html",
        theme: "original",
        reportFileName: "#{report_filename}.html",
        reportDir: @zap_home_dir,
        display: "false"
      )
      FileUtils.move( "#{@zap_home_dir}/#{report_filename}.html", "#{output_dir}/#{report_filename}.html" )
      FileUtils.move( "#{@zap_home_dir}/#{report_filename}", "#{output_dir}/#{report_filename}" )

    end

    report_filename = "zap-report-#{timestamp}.json"
    zap.reports_generate(
      title: "ZAP Scanning Report JSON",
      template: "traditional-json-plus",
      reportFileName: report_filename,
      reportDir: @zap_home_dir,
      display: "false"
    )
    FileUtils.move( "#{@zap_home_dir}/#{report_filename}", "#{output_dir}/#{report_filename}" )

    puts 'Done.'
  end


  def auth_token_loop( zap, ctx_id )

    begin
      setup_auth_token(zap, ctx_id)
    rescue => e
      raise e
    end

    task = Concurrent::TimerTask.new(
      execution_interval: @auth_token_duration
    ) { setup_auth_token(zap, ctx_id) }
    task.execute

    task

  end


  def get_name_from_xml( file, type )
    
    if !File.exist?( file )
      return "Default #{type.capitalize}"
    end

    xmlfile = File.new( file, 'r' )
    xmldoc = Document.new( xmlfile )
    if type == "context"
      type += "/name"
    end
    xmldoc.elements["/configuration/#{type}"].text
  end


  def start

    puts
    puts '=================='
    puts '== ZAP Scanning =='
    puts '=================='
    puts

    # Import Zap context and policy
    begin
      zap = build_zap
    rescue => e
      return quit_zap [ "build_zap", e ]
    end

    begin
      move_files_to_zap_home
    rescue => e
      return quit_zap [ "Missing swagger files directory named in salus.yaml file or default location.", e ]
    end

    ctx_id = build_context( zap )

    api_host_url = get_api_host_url( zap, ctx_id )

    # Clear previous results
    zap.core_deleteSiteNode( url: api_host_url )
    
    # Get auth token
    if not @skip_auth
      begin
        @auth_token_loop_thread = auth_token_loop(zap, ctx_id)
      rescue => e
        return quit_zap [ "auth_token_loop", e ]
      end
    end
    
    # Import swagger/openapi files (implicitly start passive scan)
    zap.pscan_enableAllScanners
    import_api_files( zap, api_host_url )

    # Start active scan
    scan_id = active_scan(zap, ctx_id)

    # Display progress bar for active scans
    progress(zap, scan_id)

    # Kill auth token thread
    if not @skip_auth
      @auth_token_loop_thread.shutdown
    end

    # Export results
    write_reports( zap, @output_dir )

    puts 'Scan Finished!'

    # Return @findings for exit code (0 for no findings, 1 for 1+ findings)
    @findings

  end

  def quit_zap( err )
    pp err
    @auth_token_loop_thread&.shutdown
    false
  end

end
