#!/usr/bin/python3
#-*- coding:utf-8 -*-

import numpy as np
import json
import os
import time
import xlrd
import pickle
from sklearn.model_selection import StratifiedShuffleSplit
import pandas as pd
from scipy.stats import skew,kurtosis
import sys
import csv
import copy
import tqdm
import random
import shutil
import dataset_generation

import data_preprocess
import open_dataset_deal

# Base path configuration
BASE_PATH = "/mnt/i/ET-BERT"
DATASET_NAME = "CSTNet-TLS1.3"  # Current dataset name

# Dataset configurations
_category = 120  # dataset class

# Dataset specific paths
DATASET_BASE = os.path.join(BASE_PATH, "datasets", DATASET_NAME)
DATASETS_DIR = DATASET_BASE  # the path to save dataset for fine-tuning
PCAP_PATH = os.path.join(DATASET_BASE, "splitcap")  # 修改为 splitcap 目录
DATASET_SAVE_PATH = os.path.join(DATASET_BASE, "results")  # 结果保存目录
IF_SPLIT_PCAP = False

# Default configurations
DEFAULT_SAMPLES = [10]  # 减小默认样本数，避免采样错误
DEFAULT_FEATURES = ["payload"]
DEFAULT_DATASET_LEVEL = "packet"

def ensure_directories():
    """Ensure all necessary directories exist"""
    directories = [
        PCAP_PATH,
        DATASET_SAVE_PATH,
        os.path.join(DATASET_SAVE_PATH, "dataset")
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Ensured directory exists: {directory}")

def check_pcap_files(directory):
    """Check if directory contains any pcap files"""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(('.pcap', '.pcapng')):
                return True
    return False

def dataset_extract(model, pcap_path=PCAP_PATH, dataset_save_path=DATASET_SAVE_PATH, 
                   samples=DEFAULT_SAMPLES, features=DEFAULT_FEATURES, 
                   dataset_level=DEFAULT_DATASET_LEVEL):
    """Extract dataset for model training"""
    
    # Ensure directories exist
    ensure_directories()
    
    # Check if pcap files exist
    if not check_pcap_files(pcap_path):
        print(f"No pcap files found in {pcap_path}")
        print("Please place your pcap files in the directory first.")
        return None, None

    X_dataset = {}
    Y_dataset = {}

    try:
        dataset_dir = os.path.join(dataset_save_path, "dataset")
        if os.path.exists(dataset_dir) and os.listdir(dataset_dir):
            print(f"Reading dataset from {dataset_dir} ...")
            
            # Load numpy arrays
            data_files = {
                'x_train': 'x_datagram_train.npy',
                'x_test': 'x_datagram_test.npy',
                'x_valid': 'x_datagram_valid.npy',
                'y_train': 'y_train.npy',
                'y_test': 'y_test.npy',
                'y_valid': 'y_valid.npy'
            }
            
            loaded_data = {}
            for key, filename in data_files.items():
                file_path = os.path.join(dataset_dir, filename)
                loaded_data[key] = np.load(file_path, allow_pickle=True)
            
            X_dataset, Y_dataset = models_deal(
                model, X_dataset, Y_dataset,
                loaded_data['x_train'], loaded_data['x_test'], loaded_data['x_valid'],
                loaded_data['y_train'], loaded_data['y_test'], loaded_data['y_valid']
            )

            return X_dataset, Y_dataset
    except Exception as e:
        print(f"Error reading dataset: {str(e)}")
        print(f"Dataset directory {dataset_dir} not exist.\nBegin to obtain new dataset.")

    # Create record file directory
    record_dir = os.path.dirname(os.path.join(dataset_save_path, "picked_file_record"))
    os.makedirs(record_dir, exist_ok=True)

    X, Y = dataset_generation.generation(
        pcap_path=pcap_path,
        samples=samples,
        features=features,
        splitcap=IF_SPLIT_PCAP,
        dataset_save_path=dataset_save_path,
        dataset_level=dataset_level
    )

    dataset_statistic = [0] * _category

    X_payload= []
    Y_all = []
    for app_label in Y:
        for label in app_label:
            Y_all.append(int(label))
    for label_id in range(_category):
        for label in Y_all:
            if label == label_id:
                dataset_statistic[label_id] += 1
    print("category flow")
    for index in range(len(dataset_statistic)):
        print("%s\t%d" % (index, dataset_statistic[index]))
    print("all\t%d" % (sum(dataset_statistic)))

    for i in range(len(features)):
        if features[i] == "payload":
            for index_label in range(len(X[0])):
                for index_sample in range(len(X[0][index_label])):
                    X_payload.append(X[0][index_label][index_sample])

    split_1 = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=41) 
    split_2 = StratifiedShuffleSplit(n_splits=1, test_size=0.5, random_state=42) 

    x_payload = np.array(X_payload)
    dataset_label = np.array(Y_all)

    x_payload_train = []
    y_train = []

    x_payload_valid = []
    y_valid = []

    x_payload_test = []
    y_test = []

    for train_index, test_index in split_1.split(x_payload, dataset_label):
        x_payload_train, y_train = x_payload[train_index], dataset_label[train_index]
        x_payload_test, y_test = x_payload[test_index], dataset_label[test_index]
    for test_index, valid_index in split_2.split(x_payload_test, y_test):
        x_payload_valid, y_valid = x_payload_test[valid_index], y_test[valid_index]
        x_payload_test, y_test = x_payload_test[test_index], y_test[test_index]

    # Create dataset directory
    dataset_dir = os.path.join(dataset_save_path, "dataset")
    os.makedirs(dataset_dir, exist_ok=True)

    # Define output paths
    output_paths = {
        'x_train': os.path.join(dataset_dir, 'x_datagram_train.npy'),
        'x_test': os.path.join(dataset_dir, 'x_datagram_test.npy'),
        'x_valid': os.path.join(dataset_dir, 'x_datagram_valid.npy'),
        'y_train': os.path.join(dataset_dir, 'y_train.npy'),
        'y_test': os.path.join(dataset_dir, 'y_test.npy'),
        'y_valid': os.path.join(dataset_dir, 'y_valid.npy')
    }

    # Save data
    np.save(output_paths['x_train'], x_payload_train)
    np.save(output_paths['x_test'], x_payload_test)
    np.save(output_paths['x_valid'], x_payload_valid)
    np.save(output_paths['y_train'], y_train)
    np.save(output_paths['y_test'], y_test)
    np.save(output_paths['y_valid'], y_valid)

    X_dataset, Y_dataset = models_deal(model, X_dataset, Y_dataset,
                                       x_payload_train, x_payload_test, x_payload_valid,
                                       y_train, y_test, y_valid)

    return X_dataset,Y_dataset

def models_deal(model, X_dataset, Y_dataset, x_payload_train, x_payload_test, x_payload_valid, y_train, y_test, y_valid):
    for index in range(len(model)):
        print(f"Begin to model {model[index]} dealing...")
        x_train_dataset = []
        x_test_dataset = []
        x_valid_dataset = []

        if model[index] == "pre-train":
            save_dir = DATASETS_DIR
            write_dataset_tsv(x_payload_train, y_train, save_dir, "train")
            write_dataset_tsv(x_payload_test, y_test, save_dir, "test")
            write_dataset_tsv(x_payload_valid, y_valid, save_dir, "valid")
            print(f"finish generating pre-train's datagram dataset.\nPlease check in {save_dir}")
            unlabel_data(os.path.join(save_dir, "test_dataset.tsv"))

        X_dataset[model[index]] = {"train": [], "valid": [], "test": []}
        Y_dataset[model[index]] = {"train": [], "valid": [], "test": []}

        X_dataset[model[index]]["train"], Y_dataset[model[index]]["train"] = x_train_dataset, y_train
        X_dataset[model[index]]["valid"], Y_dataset[model[index]]["valid"] = x_valid_dataset, y_valid
        X_dataset[model[index]]["test"], Y_dataset[model[index]]["test"] = x_test_dataset, y_test

    return X_dataset, Y_dataset

def write_dataset_tsv(data, label, file_dir, type):
    """Write dataset to TSV file"""
    dataset_file = [["label", "text_a"]]
    for index in range(len(label)):
        dataset_file.append([label[index], data[index]])
    
    output_file = os.path.join(file_dir, f"{type}_dataset.tsv")
    with open(output_file, 'w', newline='') as f:
        tsv_w = csv.writer(f, delimiter='\t')
        tsv_w.writerows(dataset_file)
    return 0

def unlabel_data(label_data):
    nolabel_data = ""
    with open(label_data,newline='') as f:
        data = csv.reader(f,delimiter='\t')
        for row in data:
            nolabel_data += row[1] + '\n'
    nolabel_file = label_data.replace("test_dataset","nolabel_test_dataset")
    #nolabel_file = label_data.replace("train_dataset", "nolabel_train_dataset")
    with open(nolabel_file, 'w',newline='') as f:
        f.write(nolabel_data)
    return 0

def cut_byte(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    remanent_count = len(result[0])%2
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def pickle_save_data(path_file, data):
    with open(path_file, "wb") as f:
        pickle.dump(data, f)
    return 0

def count_label_number(samples):
    new_samples = samples * _category
    
    splitcap_path = os.path.join(PCAP_PATH, 'splitcap') if 'splitcap' not in PCAP_PATH else PCAP_PATH
    dataset_length, labels = open_dataset_deal.statistic_dataset_sample_count(splitcap_path)

    for index in range(len(dataset_length)):
        if dataset_length[index] < samples[0]:
            print(f"label {labels[index]} has less sample's number than defined samples {samples[0]}")
            new_samples[index] = dataset_length[index]
    return new_samples

if __name__ == '__main__':
    # Configuration flags
    open_dataset_not_pcap = False  # Convert pcapng to pcap
    file2dir = True               # Generate category directories first
    splitcap_finish = False       # Initialize sample number array
    ml_experiment = False         # Machine learning experiment flag
    
    print("Current configuration:")
    print(f"PCAP_PATH: {PCAP_PATH}")
    print(f"DATASET_SAVE_PATH: {DATASET_SAVE_PATH}")
    print(f"Dataset level: {DEFAULT_DATASET_LEVEL}")
    print(f"Sample size: {DEFAULT_SAMPLES[0]}")
    
    # Ensure all necessary directories exist
    ensure_directories()
    
    # Check if source directory has pcap files
    if not check_pcap_files(PCAP_PATH):
        print(f"\nNo pcap files found in {PCAP_PATH}")
        print("Please add your pcap files first.")
        sys.exit(1)
    
    # Process based on flags
    if open_dataset_not_pcap:
        print("Converting non-pcap files to pcap format...")
        for p, d, f in os.walk(PCAP_PATH):
            for file in tqdm.tqdm(f, desc="Converting files"):
                if not file.lower().endswith('.pcap'):
                    target_file = file.replace('.', '_new.')
                    source_path = os.path.join(p, file)
                    target_path = os.path.join(p, target_file)
                    open_dataset_deal.file_2_pcap(source_path, target_path)
                    if '_new.pcap' not in file:
                        os.remove(source_path)

    if file2dir:
        print("Organizing files into directories...")
        open_dataset_deal.dataset_file2dir(PCAP_PATH)

    # Calculate samples based on splitcap status
    samples = count_label_number(DEFAULT_SAMPLES) if splitcap_finish else [DEFAULT_SAMPLES[0]] * _category

    # Model training
    train_model = ["pre-train"]
    print("\nStarting dataset extraction...")
    dataset_extract(
        model=train_model,
        pcap_path=PCAP_PATH,
        dataset_save_path=DATASET_SAVE_PATH,
        samples=samples,
        features=DEFAULT_FEATURES,
        dataset_level=DEFAULT_DATASET_LEVEL
    )
