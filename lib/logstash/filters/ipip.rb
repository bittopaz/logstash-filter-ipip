# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"


module SeventeenMon
  class IPDBX
  
    private_class_method :new
  
    def ip_db_path
      @ip_db_path ||= File.expand_path'../../../../vendor/ipip.datx', __FILE__
    end
  
    def ip_db
      @ip_db ||= File.open ip_db_path, 'rb'
    end
  
    def offset
      @offset ||= ip_db.read(4).unpack("Nlen")[0]
    end
  
    def index
      @index ||= ip_db.read(offset - 4)
    end
  
    def max_comp_length
      @max_comp_length ||= offset - 262144 - 4
    end
  
    def self.instance
      @instance ||= self.send :new
    end
  
    def seek(_offset, length)
      IO.read(ip_db_path, length, offset + _offset - 262144).split "\t"
    end
  end
  
  class IP
    attr_reader :ip
  
    # Initialize IP object
    #
    # == parameters:
    # params::
    #   Might contain address(hostname) and protocol, or just IP
    #
    # == Returns:
    # self
    #
    def initialize(params = {})
      @ip = params[:ip] ||
        Socket.getaddrinfo(params[:address], params[:protocol])[0][3]
    end
  
    def four_number
      @four_number ||= begin
        fn = ip.split(".").map(&:to_i)
        raise "ip is no valid" if fn.length != 4 || fn.any?{ |d| d < 0 || d > 255}
        fn
      end
    end
  
    def ip2long
      @ip2long ||= ::IPAddr.new(ip).to_i
    end
  
    def packed_ip
      @packed_ip ||= [ ip2long ].pack 'N'
    end
  
    def find
      tmp_offset = (four_number[0] * 256 + four_number[1]) * 4
      start = IPDBX.instance.index[tmp_offset..(tmp_offset + 3)].unpack("V")[0] * 9 + 262144
  
      index_offset = -1
  
      while start < IPDBX.instance.max_comp_length
        if IPDBX.instance.index[start..(start + 3)] >= packed_ip
          index_offset = "#{IPDBX.instance.index[(start + 4)..(start + 6)]}\x0".unpack("V")[0]
          index_length = IPDBX.instance.index[(start + 8)].unpack("C")[0]
          break
        end
        start += 9
      end
  
      return "N/A" unless index_offset
  
      result = IPDBX.instance.seek(index_offset, index_length).map do |str|
        str.encode("UTF-8", "UTF-8")
      end
  
    {
      country: result[0],
      province: result[1],
      city: result[2],
      carrier: result[4]
    }
    end
  end
end

module SeventeenMon
  require "socket"
  require "ipaddr"

  def self.find_by_ip(_ip)
    IP.new(ip: _ip).find
  end
end

SM = SeventeenMon

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::IPIP < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   ipip {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "ipip"
  
  # The field containing the IP address to map via ipip.
  config :source, :validate => :string, :require => true
  
  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all ipip fields
  # are included in the event.
  #
  # For the built-in GeoLiteCity database, the following are available:
  # `city_name`, `continent_code`, `country_code2`, `country_code3`, `country_name`,
  # `dma_code`, `ip`, `latitude`, `longitude`, `postal_code`, `region_name` and `timezone`.
  #config :fields, :validate => :array

  # Specify the field into which Logstash should store the geoip data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the GeoIP information of both IPs.
  #
  # If you save the data to a target field other than `geoip` and want to use the
  # `geo\_point` related functions in Elasticsearch, you need to alter the template
  # provided with the Elasticsearch output and configure the output to use the
  # new template.
  #
  # Even if you don't use the `geo\_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'ipip'


  public
  def register
    # nothing need here
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    ipip_data = nil

    begin
      ip = event[@source]
      ip = ip.first if ip.is_a? Array
      ipip_data =  SM.find_by_ip ip
    rescue Exception => e
      @logger.error("Unknown error while looking up IPIP data", :exception => e, :field => @field, :event => event)
    end

    event[@target] = {} if event[@target].nil?

    ipip_data.each do |key, value|
      event[@target][key.to_s] = value
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::IPIP
