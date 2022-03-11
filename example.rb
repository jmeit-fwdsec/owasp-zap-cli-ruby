require 'yaml'
require './zap'

config_file = File.read( './eureka-dynamic.yaml' )
config = YAML.load( config_file )

zap_config = config['scanner_configs']['Zap']

zap = ZapScan.new(
    zap_home_dir: '/private/tmp/',#'eureka/zap',
    zap_api_key: 'cs5pvv51qmcp3srlenbs7kms3b', 
    zap_port: '8081',
    api_files_dir: zap_config['api_files_dir'],
    api_files_type: zap_config['api_files_type'],
    context_file: zap_config['context_file'],
    policy_file: zap_config['policy_file'],
    skip_auth: zap_config['skip_auth'],
    auth_token_duration: 300 - 10, #5min w/ a 10s buffer
    custom_auth_script_file: zap_config['custom_auth_script_file']
)
zap.start
