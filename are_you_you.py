# Copyright (C) 2020 Ana Maria Martinez Gomez <anamaria@martinezgomez.name>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <https://www.gnu.org/licenses>.
#
# SPDX-License-Identifier: GPLv3-or-later

# INSTRUCTIONS
# To run it just execute (tried with Python 3.6.10):
# python -W ignore are_you_you.py
#
# It parses the logs and prints false positives and intrusion detection rates
# using several ML algorithms and different windows sizes.


import numpy as np
import json
from statistics import mean, stdev
from sklearn import mixture
from sklearn.ensemble import IsolationForest
from sklearn.covariance import EllipticEnvelope


# Train data (my data)
my_paths1 = ['logs/day1.log', 'logs/day2.log', 'logs/day3.log', 'logs/day4.log']
# Extra path with my data to evaluate the false positives rate
my_paths2 = ['logs/day5.log']
# Adversary data
adversary_paths = ['logs/malicious.log']
window_sizes = [2, 5, 10] # minutes

command_indexes = { 'sudo': 9, 'la': 10, 'vim': 11, 'cd': 12, 'git': 13, 'open': 14, 'cp': 15, 'driveup': 16, 'irb': 17, 'other': 18 }

def number(snapshot):
    return int(snapshot[0]['number'])


def update_mean_stdev(index, data, num_processes, num_ports):
    if len(num_processes) > 0:
        data[index][0] = round(mean(num_processes), 2)
    if len(num_processes) > 1:
        data[index][1] = round(stdev(num_processes), 2)
    if len(num_ports) > 0:
        data[index][2] = round(mean(num_ports), 2)
    if len(num_ports) > 1:
        data[index][3] = round(stdev(num_ports), 2)


def update_commands(index, data, previous_total):
    new_total =  data[index][9:19]
    if all(value == 0 for value in new_total):
        return
    for i in range(10):
        data[index][i+9] -= previous_total[i]
    previous_total = new_total


def number_processes(snapshot, num_processes):
    num_processes.append(number(snapshot))


def number_listening_ports(snapshot, num_ports):
    num_ports.append(number(snapshot))


def processes_created(snapshot, index, data):
    data[index][4] += number(snapshot)


def file_changes(snapshot, index, data):
    data[index][5] += number(snapshot)


def documents_touched(snapshot, index, data):
    data[index][6] += number(snapshot)


def files_moved(snapshot, index, data):
    data[index][7] += number(snapshot)


def decoys_activated(snapshot, index, data):
    data[index][8] += number(snapshot)


def shell_commands(snapshot, index, data):
    for entry in snapshot:
        command_index = command_indexes[entry['command']]
        data[index][command_index] = int(entry['number'])


def data_for(file_paths, window_size):
    data = []
    index = -1
    for file_path in file_paths:
        previous_total = [0] * 10 # history reseted before starting osqueryd
        num_processes = num_ports = []
        window_timestamp = 0
        with open(file_path, 'r') as file_object:
            line = file_object.readline()
            while line:
                entry = json.loads(line)
                if (entry['unixTime'] >= window_timestamp + 60 * window_size):
                    if window_timestamp > 0:
                        update_mean_stdev(index, data, num_processes, num_ports)
                        num_processes = num_ports = []
                        update_commands(index, data, previous_total)
                    window_timestamp = entry['unixTime']
                    index += 1
                    data.append([0] * 19)

                if entry['name'] == 'number_processes':
                    number_processes(entry['snapshot'], num_processes)
                elif entry['name'] == 'number_listening_ports':
                    number_listening_ports(entry['snapshot'], num_ports)
                else:
                    func = eval(entry['name'])
                    func(entry['snapshot'], index, data)

                line = file_object.readline()

            # last window may be shorter, not reliable
            data = data[:-1]
            index -= 1

    return(data)


def mean_rate(array):
    return round(mean(array) * 100, 2)


def print_algorithm_rates(false_positives, intrusion_detections):
    print('    False positives rate', mean_rate(false_positives))
    print('    Intrusion detection rate: ', mean_rate(intrusion_detections))


def anomalies_rate_clustering(prediction, value):
    values = np.full(len(prediction), int(value))
    return np.mean(values > prediction)


def train_clustering(algorithm, data, margin=2):
    print('  Using ' + algorithm.__class__.__name__)

    # Use several seeds to get a deterministic realistic value
    false_positives = []
    intrusion_detections = []
    for i in range(1,11):
        algorithm.random_state = np.random.RandomState(i)
        ml_model = algorithm.fit(data[0])
        my_score = ml_model.score(data[0]) * margin
        prediction = ml_model.score_samples(data[1])
        false_positives.append(anomalies_rate_clustering(prediction, my_score))

        # Train with extra-day
        ml_model = algorithm.fit(data[2])
        my_score = ml_model.score(data[2]) * margin
        prediction = ml_model.score_samples(data[3])
        intrusion_detections.append(anomalies_rate_clustering(prediction, my_score))

    print_algorithm_rates(false_positives, intrusion_detections)


def anomalies_rate(prediction):
    values = np.ones(len(prediction))
    return np.mean(values != prediction)


def train_anomaly_detection(algorithm, data, details=''):
    print('  Using ' + algorithm.__class__.__name__ + ' ' + details)

    # Use several seeds to get a deterministic realistic value
    false_positives = []
    intrusion_detections = []
    for i in range(1,11):
        algorithm.random_state = np.random.RandomState(i)
        ml_model = algorithm.fit(data[0])
        prediction = ml_model.predict(data[1])
        false_positives.append(anomalies_rate(prediction))

        # Train with extra-day
        ml_model = algorithm.fit(data[2])
        prediction = ml_model.predict(data[3])
        intrusion_detections.append(anomalies_rate(prediction))

    print_algorithm_rates(false_positives, intrusion_detections)


for window_size in window_sizes:
    print('Windows size: ' + str(window_size))
    data = [data_for(my_paths1, window_size),
            data_for(my_paths2, window_size),
            data_for(my_paths1 + my_paths2, window_size),
            data_for(adversary_paths, window_size)]
    # Fix the random seed because we like deterministic algorithms
    seed = np.random.RandomState(38)
    train_clustering(mixture.GaussianMixture(n_components=10, covariance_type='diag', random_state=seed), data)
    train_anomaly_detection(IsolationForest(n_estimators=100, random_state=seed), data)
    for outliers_fraction in [0.01, 0.3]:
        details = 'contamination = ' + str(outliers_fraction)
        train_anomaly_detection(EllipticEnvelope(contamination=outliers_fraction, random_state=seed), data, details)

