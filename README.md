# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

This filter is part of the redBorder malware pipeline process, updates a key in aersopike evertime we recieve a message.

## Documentation

Add the redfish input in your Logstash pipeline as follow:

```sh
filter {
   scores {  }
}
```

## Need Help?

Need help? Try sending us an email to support@redborder.com

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed:
```sh 
rvm install jruby-9.2.6.0
```

- Clone from the GitHub [logstash-filter-scores](https://github.com/redBorder/logstash-filter-scores)

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in an installed Logstash

- Build your plugin gem
```sh
gem build logstash-filter-scores.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.
