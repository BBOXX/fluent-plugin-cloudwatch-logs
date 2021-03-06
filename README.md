# fluent-plugin-cloudwatch-logs

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-cloudwatch-logs.svg)](http://badge.fury.io/rb/fluent-plugin-cloudwatch-logs)

[CloudWatch Logs](http://aws.amazon.com/blogs/aws/cloudwatch-log-service/) Plugin for Fluentd

## Installation

    $ gem install fluent-plugin-cloudwatch-logs

## Preparation

Create IAM user with a policy like the following:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:*",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:logs:us-east-1:*:*",
        "arn:aws:s3:::*"
      ]
    }
  ]
}
```

Set region and credentials:

```
$ export AWS_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY"
$ export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
```

## Example

Start fluentd:

```
$ fluentd -c example/fluentd.conf
```

Send sample log to CloudWatch Logs:

```
$ echo '{"hello":"world"}' | fluent-cat test.cloudwatch_logs.out
```

Fetch sample log from CloudWatch Logs:

```
# stdout
2014-07-17 00:28:02 +0900 test.cloudwatch_logs.in: {"hello":"world"}
```

## Configuration
### out_cloudwatch_logs

```
<match tag>
  type cloudwatch_logs
  log_group_name log-group-name
  log_stream_name log-stream-name
  auto_create_stream true
  #message_keys key1,key2,key3,...
  #max_message_length 32768
  #use_tag_as_group false
  #use_tag_as_stream false
  #include_time_key true
  #localtime true
  #log_group_name_key group_name_key
  #log_stream_name_key stream_name_key
  #remove_log_group_name_key true
  #remove_log_stream_name_key true
  #put_log_events_retry_wait 1s
  #put_log_events_retry_limit 17
  #put_log_events_disable_retry_limit false
</match>
```

* `log_group_name`: name of log group to store logs
* `log_stream_name`: name of log stream to store logs
* `auto_create_stream`: to create log group and stream automatically
* `message_keys`: keys to send messages as events
* `max_message_length`: maximum length of the message
* `max_events_per_batch`: maximum number of events to send at once (default 10000)
* `use_tag_as_group`: to use tag as a group name
* `use_tag_as_stream`: to use tag as a stream name
* `include_time_key`: include time key as part of the log entry (defaults to UTC)
* `localtime`: use localtime timezone for `include_time_key` output (overrides UTC default)
* `log_group_name_key`: use specified field of records as log group name
* `log_stream_name_key`: use specified field of records as log stream name
* `remove_log_group_name_key`: remove field specified by `log_group_name_key`
* `remove_log_stream_name_key`: remove field specified by `log_stream_name_key`
* `put_log_events_retry_wait`: time before retrying PutLogEvents (retry interval increases exponentially like `put_log_events_retry_wait * (2 ^ retry_count)`)
* `put_log_events_retry_limit`: maximum count of retry (if exceeding this, the events will be discarded)
* `put_log_events_disable_retry_limit`: if true, `put_log_events_retry_limit` will be ignored

### in_cloudwatch_logs

```
<source>
  type cloudwatch_logs
  tag cloudwatch.in
  log_group_name group
  log_stream_name stream
  #use_log_stream_name_prefix true
  state_file /var/lib/fluent/group_stream.in.state
</source>
```

* `tag`: fluentd tag
* `log_group_name`: name of log group to fetch logs
* `log_stream_name`: name of log stream to fetch logs
* `use_log_stream_name_prefix`: to use `log_stream_name` as log stream name prefix (default false)
* `state_file`: file to store current state (e.g. next\_forward\_token)
* `start_days_ago`: maximum number of past days events to request at start up (default is no maximum, collect all available events)

This plugin uses [fluent-mixin-config-placeholders](https://github.com/tagomoris/fluent-mixin-config-placeholders) and you can use addtional variables such as %{hostname}, %{uuid}, etc. These variables are useful to put hostname in `log_stream_name`.

## Test

Set credentials:

```
$ export AWS_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY"
$ export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_KEY"
```

Run tests:

```
$ rake test
```

Or, If you do not want to use IAM roll or ENV(this is just like writing to configuration file) :

```
$ rake aws_key_id=YOUR_ACCESS_KEY aws_sec_key=YOUR_SECRET_KEY region=us-east-1 test
```

## Caution

- If an event message exceeds API limit (256KB), the event will be discarded.

## TODO

* out_cloudwatch_logs
  * if the data is too big for API, split into multiple requests
  * format
  * check data size
* in_cloudwatch_logs
  * format
  * fallback to start_time because next_token expires after 24 hours

## Contributing

1. Fork it ( https://github.com/[my-github-username]/fluent-plugin-cloudwatch-logs/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
