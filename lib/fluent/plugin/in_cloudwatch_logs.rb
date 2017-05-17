module Fluent
  require 'fluent/mixin/config_placeholders'
  require 'json'

  class CloudwatchLogsInput < Input
    Plugin.register_input('cloudwatch_logs', self)

    include Fluent::Mixin::ConfigPlaceholders

    # Define `router` method of v0.12 to support v0.10.57 or earlier
    unless method_defined?(:router)
      define_method("router") { Engine }
    end

    config_param :aws_key_id, :string, :default => nil, :secret => true
    config_param :aws_sec_key, :string, :default => nil, :secret => true
    config_param :region, :string, :default => nil
    config_param :tag, :string
    config_param :log_group_name, :string
    config_param :log_stream_name, :string
    config_param :use_log_stream_name_prefix, :bool, default: false
    config_param :state_file, :string
    config_param :fetch_interval, :time, default: 60
    config_param :http_proxy, :string, default: nil
    config_param :start_days_ago, :integer, default: nil

    def initialize
      super

      require 'aws-sdk-core'
    end

    def placeholders
      [:percent]
    end

    def configure(conf)
      super
      configure_parser(conf)
    end

    def start
      $log.trace "Top of CloudwatchLogsInput.start"

      # needed to make the multi-threading work correctly
      Aws.eager_autoload!

      @from_event_timestamp = NIL
      if @start_days_ago
        start_seconds_ago = @start_days_ago * 24 * 60 * 60
        from_event_time = Time.now - start_seconds_ago
        # AWS timestamps are number of milliseconds since Jan 1, 1970 00:00:00 UTC
        @from_event_timestamp = from_event_time.to_i * 1000
      end

      @finished = false
      @thread = Thread.new(&method(:run))
      # this causes fluentd to stop completely if an exception occurs in the plugin's thread. This makes
      # exceptions easier to track down, but shouldn't be there in production
      @thread.abort_on_exception = true
    end

    def shutdown
      @finished = true
      @thread.join
    end

    private
    def configure_parser(conf)
      if conf['format']
        @parser = TextParser.new
        @parser.configure(conf)
      end
    end

    def state_file_name(log_stream_name)
      name = @state_file
      name = "#{@state_file}_#{log_stream_name}" if log_stream_name
      return name
    end

    def next_token(log_stream_name)
      state_file = state_file_name(log_stream_name)
      $log.trace "next_token. state_file: " + state_file
      return nil unless File.exist?(state_file)
      token = File.read(state_file).chomp
      $log.trace "next_token. token: " + token
      return token
    end

    def store_next_token(token, log_stream_name = nil)
      state_file = state_file_name(log_stream_name)
      $log.trace "store_next_token. state_file: " + state_file + ". token: " + token
      open(state_file, 'w') do |f|
        f.write token
      end
    end

    def run
      options = {}
      options[:credentials] = Aws::Credentials.new(@aws_key_id, @aws_sec_key) if @aws_key_id && @aws_sec_key
      options[:region] = @region if @region
      options[:http_proxy] = @http_proxy if @http_proxy
      @logs = Aws::CloudWatchLogs::Client.new(options)

      @next_fetch_time = Time.now

      until @finished
        if Time.now > @next_fetch_time
          @next_fetch_time += @fetch_interval

          if @use_log_stream_name_prefix
            log_streams = describe_log_streams
            log_streams.each do |log_stream|
              log_stream_name = log_stream.log_stream_name
              events = get_events(log_stream_name)
              events.each do |event|
                emit(event, log_stream_name)
              end
            end
          else
            events = get_events(@log_stream_name)
            events.each do |event|
              emit(event, @log_stream_name)
            end
          end
        end
        sleep 1
      end
    end

    def emit(event, log_stream_name=NIL)
      if @parser
        record = @parser.parse(event.message)
        if record[1]
          if log_stream_name
            record[1]['_stream'] = log_stream_name
          end
          router.emit(@tag, record[0], record[1])
        end
      else
        time = (event.timestamp / 1000).floor
        record = JSON.parse(event.message)
        if record
          if log_stream_name
            record['_stream'] = log_stream_name
          end
          router.emit(@tag, time, record)
        end
      end
    end

    def get_events(log_stream_name)
      request = {
        log_group_name: @log_group_name,
        log_stream_name: log_stream_name
      }
      $log.trace "get_events. log_stream_name: " + log_stream_name
      # use next_token if there is one, otherwise use a start time if supplied
      token = next_token(log_stream_name)
      if !token.nil? && !token.empty?
        request[:next_token] = token
      elsif @from_event_timestamp
        request[:start_time] = @from_event_timestamp
      end
      response = @logs.get_log_events(request)
      store_next_token(response.next_forward_token, log_stream_name)

      response.events
    end

    def describe_log_streams(log_streams = nil, next_token = nil)
      request = {
        log_group_name: @log_group_name
      }
      request[:next_token] = next_token if (!next_token.nil? && !next_token.empty?)
      request[:log_stream_name_prefix] = @log_stream_name
      response = @logs.describe_log_streams(request)
      if log_streams
        log_streams.concat(filter_log_streams(response.log_streams))
      else
        log_streams = filter_log_streams(response.log_streams)
      end
      if response.next_token
        log_streams = describe_log_streams(log_streams, response.next_token)
      end
      log_streams
    end

    def filter_log_streams(log_streams)
      filtered_streams = []
      # discard any streams whose events are too old
      if @from_event_timestamp
        log_streams.each do |log_stream|
          if log_stream.last_event_timestamp && (log_stream.last_event_timestamp >= @from_event_timestamp)
            filtered_streams << log_stream
          end
        end
      else
        filtered_streams = log_streams
      end
      filtered_streams
    end
  end
end
