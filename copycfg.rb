#!/usr/bin/env ruby
# vim: set sw=2 sts=2 et tw=80 :

require 'yaml' #copycfg.yaml
require 'rubygems' #for net/*
require 'net/ldap'
require 'net/sftp'
require 'fileutils'
include FileUtils

## Ghetto config variables at the top of the file :3
#
# Location that all netgroup/host dirs will be in. Could just be a symlink to
# the location of the actual directory.
$topdir = "/Configs"

# Yaml configuration file for default files or host-specific settings (see
# details below).
$yaml = "/disk/copycfg/copycfg.yaml"

# SSH key used to access hosts
$key = "/root/.ssh/id_rsa"

# The number of days that a host can fail its backup before its directory is
# unshared and removed.
$days = 2

#
## End of the config

def main
  # Check correct arguments
  if ARGV.length < 1
    puts "Usage #{$0} <netgroup> [<netgroup> [...]]"
    exit 1
  end
  ARGV.each do |netgroup|
    copy_netgroup netgroup
  end
end


def copy_netgroup netgroup
  # Setup variables for netgroup, and the directory
  dir = "#{$topdir}/#{netgroup}"
  dirbak = dir + ".bak"

  # Check that the base and backup dirs exists, else create them
  exit 2 unless File.directory?(dir) || mkdir_p(dir)
  exit 5 unless File.directory?(dirbak) || mkdir_p(dirbak)

  ## Reads the yaml config for settings
  # Contains:
  # - Base dir from which configs are exported
  # - Default files to copy
  # - Host-specific files to copy
  #
  ## 'config' format:
  # config["examplegroup"] includes list of files and/or filegroups
  # config["example.cat.pdx.edu"] includes list of files and/or filegroups
  # - Used by default if it matches hostname
  # config["default"] includes list of files and/or filegroups
  # - Used if there is no hostname match
  #
  config = read_config

=begin algorithm

unshare all dirs
hash of memberNisNetgroup => each
  hash of hostnames from nisNetgroupTriple
  repeat until no memberNisNetgroups

each hostname in hash
  if it has a new copy
    new copy is older than 2 days from now
      try to make new copy
        remove new copy
        make new copy
        #old copy is of unknown origin

    new copy is not older than 2 days from now
      remove old copy
      copy new copy to old copy
      try to make new copy
        remove new copy
        make new copy
        #old copy is one or two days older than new copy
      reshare

  no new copy
    try to make new copy
      make new copy
      #old copy is of unknown origin
    reshare

for each hostdir in dir
  if dne in hash
    rm old dir
    mv new to old

=end

  # Unshare all dirs
  unshareAll dir
  # Get a hash of hostnames that should be copycfg'd
  hosts = get_hosts netgroup
  # Process each host
  hosts.each do |host|
    hostdir = "#{dir}/#{host}"
    hostdirbak = "#{dirbak}/#{host}"
    # Get all the files that should be backed up for this host
    files = backup_files host, config
    if File.exist? "#{hostdir}/.completed"
      if File.stat("#{hostdir}/.completed").ctime < (Time.now - 60*60*24*$days)
        #older than $days
        remove hostdir
      else
        #not older
        remove hostdirbak
        mv hostdir, hostdirbak #from FileUtils
      end
    end
    remove hostdir unless copy files, host, dir
    reshare dir, host
  end
end

def read_config
  # Reference:
  # http://www.yaml.org/YAML_for_ruby.html
  # http://yaml.kwiki.org/?YamlInFiveMinutes
  File.open $yaml do |yf|
    YAML::load yf
  end
end

# Create an array of hosts from a netgroup
def get_hosts netgroup
  hosts = []
  # Bind RO to ldap for recursive searching netgroup. FIXME: hardcoded
  auth = { :method => :simple, :username => 'uid=network,ou=Netgroup,dc=catnip', :password => 'sedLdapPassword' }
  Net::LDAP.open(:host => 'ldap.cat.pdx.edu', :port => 636, :auth => auth, :encryption => :simple_tls) do |ldap|
    filter = Net::LDAP::Filter.eq( "cn", netgroup )
    attrs = ["nisNetgroupTriple","memberNisNetgroup"]
    ldap.search(:base => 'ou=Netgroup,dc=catnip', :filter => filter, :attributes => attrs) do |entry|
      [*entry["nisNetgroupTriple"]].each do |triple|
        host = (/([-\w]+\.)+\w+/.match(triple)).to_s
        hosts << host unless host == ""
      end
      [*entry["memberNisNetgroup"]].each do |memberNetgroup|
        hosts += get_hosts(memberNetgroup) #get subgroups
      end
    end
  end
  return hosts
end

# Returns a list of files for a given host
# FIXME Doesn't recognize difference between defined host with 0 files and
#       undefined host. So no "blank host" definitions allowed
def backup_files host, config
  files = expand_files host, config
  files = expand_files "default", config if files.empty? # Undefined hosts get default
  return files
end

# Recursive function used by backup_files()
def expand_files map, config
  files = Array.new
  if config.has_key? map
    config[map].each do |v|
      m = /^\/.*/.match v #starts with /, otherwise it's a group name
      if m
        files << m.to_s
      else
        files + (expand_files m.to_s, config)
      end
    end
  end
  return files
end

# Unshares all directories
def unshareAll dir
  Dir.foreach dir do |hostdir|
    `unshare "#{dir}/#{hostdir}" > /dev/null 2>&1`
  end
end

# Like it sounds
def remove dir
  #rm -r's dir, but not subject to time-of-check-to-time-of-use vuln
  #puts "Removing #{dir}"
  rm_r dir, :secure => true, :force => true
end

# Copies a list of files from host to dir. Returns false if various things don't
# work
def copy files, host, dir
  dest = "#{dir}/#{host}"
  File.directory?(dest) || mkdir_p(dest)
  #puts "Connecting to #{host}"
  begin
    Net::SFTP.start(host, "root", :auth_methods => ["publickey"], :keys => [$key], :timeout => 1) do |sftp|
      files.each do |file|
        begin
          dir = File.dirname "#{dest}/#{file}"
          stats = sftp.stat! file
          if stats
            File.directory?(dir) || mkdir_p(dir)
            if stats.directory?
              sftp.download! file, "#{dest}/#{file}", :recursive => true
              chmod stats.permissions, "#{dest}/#{file}"
            else
              sftp.download! file, "#{dest}/#{file}"
              chmod stats.permissions, "#{dest}/#{file}"
            end
            touch "#{dest}/.completed" #at least one copied file. Too intensive?
          end
        rescue
          #puts "Next for #{file}"
          next #file does not exist
        end
      end
    end
  rescue Net::SFTP::Exception => e
    puts "#{host} sftp exception: #{e}"
    return false
  #rescue Net::SCP::Error => e
  #  puts "#{host} scp error: #{e}"
  #  return false
  rescue Timeout::Error => e
    puts "#{host} timeout: #{e}"
    return false
  rescue Errno::ECONNREFUSED => e
    puts "#{host} refused: #{e}"
    return false
  rescue SocketError => e
    puts "#{host} resolve: #{e}"
    return false
  rescue Net::SSH::AuthenticationFailed => e
    puts "#{host} auth failed: #{e}"
    return false
  rescue Net::SSH::Disconnect => e
    puts "#{host} disconnected: #{e}"
    return false #no access to host
  end
  return true
end

# Reshares dir/host to host only
def reshare dir, host
  if File.exist? "#{dir}/#{host}/.completed"
    `share -F nfs -o ro=#{host},anon=0 #{dir}/#{host} > /dev/null 2>&1`
  end
end

# Boilerplate
if __FILE__ == $PROGRAM_NAME
  # Commenting convention: If there is no space after the # then it's for the
  # developer, otherwise it's for the observer.
  main
end
