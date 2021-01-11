### Threat Stack API example scripts

This repository provides some example Python scripts for interacting with Threat Stack's API.

#### How to execute a script

Place a `.env` defining environment variables outlined in `tasks/settings.py`, including
* `API_KEY` - your personal API key
* `API_ID` - your user ID
* `ORG_ID` - the organization's ID
* `LOGLEVEL` - (optional) the logging level. See [logging and debugging](#logging-and-debugging) for further info about enabling additional logging while executing scripts.

#### Logging and Debugging

I've started to convert these scripts to include basic logging that you can enable by setting an environment variable `LOGLEVEL=INFO` prior to executing the scripts, like
```shell script
$ LOGLEVEL=INFO tasks/pull_audit_log.py
```