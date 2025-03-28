#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "with agent: test without -no-cs flag" {
    config_set '.common.log_media="stdout"'
    rune -0 wait-for \
        --err "Starting processing data" \
        "$CROWDSEC"
}

@test "no agent: crowdsec LAPI should run (-no-cs flag)" {
    config_set '.common.log_media="stdout"'
    rune -0 wait-for \
        --err "CrowdSec Local API listening" \
        "$CROWDSEC" -no-cs
}

@test "no agent: crowdsec LAPI should run (no crowdsec_service in configuration file)" {
    config_disable_agent
    config_log_stderr
    rune -0 wait-for \
        --err "crowdsec agent is disabled" \
        "$CROWDSEC"
}

@test "no agent: cscli config show" {
    config_set '.crowdsec_service.enable=false'
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"
    assert_output --partial "Crowdsec (disabled):"

    config_set 'del(.crowdsec_service)'
    rune -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"
    refute_output --partial "Crowdsec"
}

@test "no agent: lapi status should be ok" {
    config_disable_agent
    ./instance-crowdsec start
    rune -0 cscli lapi status
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "cscli metrics" {
    config_disable_agent
    ./instance-crowdsec start
    rune -0 cscli lapi status
    rune -0 cscli metrics
}
