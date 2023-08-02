# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/malware_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Scores < LogStash::Filters::Base
  include MalwareConstant
  include Aerospike

  config_name "scores"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                      :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],             :require => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = nil
    @aerospike_store = nil
    register_aerospike_and_set_aerospike_store
  end # def register

  public

  def register_aerospike_and_set_aerospike_store
    begin
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))
      @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace,  @reputation_servers)
    rescue Aerospike::Exceptions::Aerospike => ex
      @aerospike = nil
      @aerospike_store = nil
      @logger.error(ex.message)
    end
  end

  def filter(event)

    # Solve the problem that happen when:
    # at time of registering the plugin the
    # aerospike was not there
    register_aerospike_and_set_aerospike_store if @aerospike.nil?

    message = {}
    message = event.to_hash

    hash = message[HASH]
    timestamp = message[TIMESTAMP]

    @aerospike_store.update_hash_times(timestamp, hash, "hash")

    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Scores
