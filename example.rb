require 'yaml'
require './zap'

config_file = File.read( './vulnapp/juiceshop-zap/eureka-dynamic-native.yaml' )
config = YAML.load( config_file )

zap_config = config['scanner_configs']['Zap']

zap = ZapScan.new(
    opts: {
        'zap_home_dir' => '/private/tmp', #"#{__dir__}/eureka/zap/home",
        'zap_api_key' => 'cs5pvv51qmcp3srlenbs7kms3b', 
        'zap_port' => '8081',
        'output_dir' => "#{__dir__}/eureka/reports",
        'local_run' => true
    }.merge( zap_config )
)
zap.start
