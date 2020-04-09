# Are you you?

Determine if who is using my computer is me by training a ML model with data of how I use my computer.
This is a project for the Intrusion Detection Systems course at Columbia University.


## Data collection

Data is collected during 4 days with osquery about how I use my computer to train the ML model.
Data is collected for an extra day to evaluate the false positives rate.
Adversary data is collected for 50 minutes to determine the intrusion detection rate.

The data is collected using osquery daemon with the configuration in [osquery.conf](osquery.conf).
The collected data can be found in the [/logs](logs) directory, however the fields paths and ports have been removed for privacy concerns.


## Data processing and ML model

[are_you_you.py](are_you_you.py) parses the logs and prints false positives and intrusion detection rates using several ML algorithms and different windows sizes.
Check the file for details about how to run it.


## Report

The [/latex](latex) folder contains the latex files used to generate the project report as well as the final version [report.pdf](latex/report.pdf).
It contains details about the osquery configuration, the selected features, the collected data, the machine learning model and the results.


## Others

The following Ruby scripts were used:
- [script-command-line.rb](script-command-line.rb) generates statistics about the shell history.
- [script-generate-queries.rb](script-generate-queries.rb) generates several osquery queries (the most complicated/long ones).

Check the files for details about how to run them.


## License

Code published under GNU GENERAL PUBLIC LICENSE v3 (see [LICENSE](LICENSE)).

