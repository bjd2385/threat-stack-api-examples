### Threat Stack API example scripts

This repository provides some example Python scripts for interacting with Threat Stack's API.

#### Logging and Debugging

I've started to convert these scripts to include basic logging that you can enable by setting an environment variable `LOGLEVEL=INFO` prior to executing the scripts, like
```shell script
$ LOGLEVEL=INFO tasks/pull_audit_log.py
```