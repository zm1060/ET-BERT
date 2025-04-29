#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import sys
import copy
import xlrd
import json
import tqdm
import shutil
import pickle
import random
import binascii
import operator
import numpy as np
import pandas as pd
import scapy.all as scapy
from functools import reduce
from flowcontainer.extractor import extract

random.seed(40)

# Base path configuration
BASE_PATH = "/mnt/i/ET-BERT"
DATASET_NAME = "CSTNet-TLS1.3"  # Current dataset name

DATASET_BASE = os.path.join(BASE_PATH, "datasets", DATASET_NAME)
WORD_DIR = os.path.join(BASE_PATH, "corpora")
WORD_NAME = "encrypted_burst_burst.txt"
PCAP_PATH = os.path.join(DATASET_BASE, "pcap")
SPLITCAP_PATH = os.path.join(BASE_PATH, "SplitCap.exe")
EDITCAP_PATH = os.path.join(BASE_PATH, "editcap")  # Keep this as is since it's a system tool
DEFAULT_DATASET_SAVE_PATH = os.path.join(DATASET_BASE, "results")
TRAFFIC_PCAP_PATH = os.path.join(DATASET_BASE, "traffic_pcap")

def is_pcap_file(file_path):
    """Check if file is a valid pcap/pcapng file"""
    return file_path.lower().endswith(('.pcap', '.pcapng'))

def convert_pcapng_2_pcap(pcapng_path, pcapng_file, output_path):
    """Convert pcapng to pcap format"""
    if not pcapng_file.lower().endswith('.pcapng'):
        return 0
        
    pcap_file = os.path.join(output_path, pcapng_file.replace('.pcapng', '.pcap'))
    cmd = f"{EDITCAP_PATH} -F pcap {os.path.join(pcapng_path, pcapng_file)} {pcap_file}"
    os.system(cmd)
    return 0

def split_cap(pcap_path, pcap_file, pcap_name, pcap_label='', dataset_level='flow'):
    """Split pcap files into flows/packets"""
    if not is_pcap_file(pcap_file):
        print(f"Skipping non-pcap file: {pcap_file}")
        return None
        
    splitcap_dir = os.path.join(DATASET_BASE, "splitcap")
    if not os.path.exists(splitcap_dir):
        os.makedirs(splitcap_dir, exist_ok=True)
    
    # Extract label from the pcap file path if not provided
    if not pcap_label:
        # Get the parent directory name as the label
        pcap_label = os.path.basename(os.path.dirname(pcap_file))
    
    # Create label-specific directory in splitcap
    output_path = os.path.join(splitcap_dir, pcap_label, pcap_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Ensure pcap_file is properly quoted to handle spaces and special characters
    pcap_file = f'"{pcap_file}"' if ' ' in pcap_file else pcap_file
    output_path = f'"{output_path}"' if ' ' in output_path else output_path

    if dataset_level == 'flow':
        cmd = f"mono {SPLITCAP_PATH} -r {pcap_file} -s session -o {output_path}"
    elif dataset_level == 'packet':
        cmd = f"mono {SPLITCAP_PATH} -r {pcap_file} -s packets 1 -o {output_path}"
    
    print(f"Executing command: {cmd}")
    result = os.system(cmd)
    if result != 0:
        print(f"Warning: SplitCap command failed with exit code {result}")
    
    return output_path

def cut(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    try:
        remanent_count = len(result[0])%4
    except Exception as e:
        remanent_count = 0
        print("cut datagram error!")
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def bigram_generation(packet_datagram, packet_len = 64, flag=True):
    result = ''
    generated_datagram = cut(packet_datagram,1)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += 1
            if token_count > packet_len:
                break
            else:
                merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += ' '
    
    return result

def get_burst_feature(label_pcap, payload_len):
    feature_data = []
    try:
        packets = scapy.rdpcap(label_pcap)
        
        packet_direction = []
        feature_result = extract(label_pcap)
        for key in feature_result.keys():
            value = feature_result[key]
            packet_direction = [x // abs(x) for x in value.ip_lengths]

        if len(packet_direction) == len(packets):
            burst_data_string = ''
            burst_txt = ''
            
            for packet_index in tqdm.tqdm(range(len(packets)), 
                                        desc=f"Processing packets in {os.path.basename(label_pcap)}", 
                                        leave=False):
                packet_data = packets[packet_index].copy()
                data = (binascii.hexlify(bytes(packet_data)))
                
                packet_string = data.decode()[:2*payload_len]
                
                if packet_index == 0:
                    burst_data_string += packet_string
                else:
                    if packet_direction[packet_index] != packet_direction[packet_index - 1]:
                        length = len(burst_data_string)
                        for string_txt in cut(burst_data_string, int(length / 2)):
                            burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                            burst_txt += '\n'
                        burst_txt += '\n'
                        
                        burst_data_string = ''
                    
                    burst_data_string += packet_string
                    if packet_index == len(packets) - 1:
                        length = len(burst_data_string)
                        for string_txt in cut(burst_data_string, int(length / 2)):
                            burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                            burst_txt += '\n'
                        burst_txt += '\n'
            
            with open(os.path.join(WORD_DIR, WORD_NAME),'a') as f:
                f.write(burst_txt)
    except Exception as e:
        print(f"Error processing {label_pcap}: {str(e)}")
    return 0

def get_feature_packet(label_pcap,payload_len):
    feature_data = []

    packets = scapy.rdpcap(label_pcap)
    packet_data_string = ''  

    for packet in packets:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()
            new_packet_string = packet_string[76:]
            packet_data_string += bigram_generation(new_packet_string, packet_len=payload_len, flag = True)
            break

    feature_data.append(packet_data_string)
    return feature_data

def get_feature_flow(label_pcap, payload_len, payload_pac):
    
    feature_data = []
    packets = scapy.rdpcap(label_pcap)
    packet_count = 0  
    flow_data_string = '' 

    feature_result = extract(label_pcap, filter='tcp', extension=['tls.record.content_type', 'tls.record.opaque_type', 'tls.handshake.type'])
    if len(feature_result) == 0:
        feature_result = extract(label_pcap, filter='udp')
        if len(feature_result) == 0:
            return -1
        extract_keys = list(feature_result.keys())[0]
        if len(feature_result[label_pcap, extract_keys[1], extract_keys[2]].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    elif len(packets) < 3:
        print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
        return -1
    try:
        if len(feature_result[label_pcap, 'tcp', '0'].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    except Exception as e:
        print("*** this flow begings from 1 or other numbers than 0.")
        for key in feature_result.keys():
            if len(feature_result[key].ip_lengths) < 3:
                print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
                return -1

    if feature_result.keys() == {}.keys():
        return -1
    
    if feature_result == {}:
        return -1
    feature_result_lens = len(feature_result.keys())
    for key in feature_result.keys():
        value = feature_result[key]

    packet_index = 0
    for packet in packets:
        packet_count += 1
        if packet_count == payload_pac:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag = True)
            break
        else:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag = True)
    feature_data.append(flow_data_string)

    return feature_data

def generation(pcap_path, samples, features, splitcap = False, payload_length = 128, payload_packet = 5, dataset_save_path = DEFAULT_DATASET_SAVE_PATH, dataset_level = "flow"):
    if os.path.exists(os.path.join(dataset_save_path, "dataset.json")):
        print("the pcap file of %s is finished generating."%pcap_path)
        
        clean_dataset = 0
        re_write = 0

        if clean_dataset:
            with open(os.path.join(dataset_save_path, "dataset.json"), "r") as f:
                new_dataset = json.load(f)
            pop_keys = ['1','10','16','23','25','71']
            print("delete domains.")
            for p_k in pop_keys:
                print(new_dataset.pop(p_k))
            
            change_keys = [str(x) for x in range(113, 119)]
            relation_dict = {}
            for c_k_index in range(len(change_keys)):
                relation_dict[change_keys[c_k_index]] = pop_keys[c_k_index]
                new_dataset[pop_keys[c_k_index]] = new_dataset.pop(change_keys[c_k_index])
            with open(os.path.join(dataset_save_path, "dataset.json"), "w") as f:
                json.dump(new_dataset, fp=f, ensure_ascii=False, indent=4)
        elif re_write:
            with open(os.path.join(dataset_save_path, "dataset.json"), "r") as f:
                old_dataset = json.load(f)
            os.renames(os.path.join(dataset_save_path, "dataset.json"), os.path.join(dataset_save_path, "old_dataset.json"))
            with open(os.path.join(dataset_save_path, "new-samples.txt"), "r") as f:
                source_samples = f.read().split('\n')
            new_dataset = {}
            samples_count = 0
            for i in range(len(source_samples)):
                current_class = source_samples[i].split('\t')
                if int(current_class[1]) > 9:
                    new_dataset[str(samples_count)] = old_dataset[str(i)]
                    samples_count += 1
                    print(old_dataset[str(i)]['samples'])
            with open(os.path.join(dataset_save_path, "dataset.json"), "w") as f:
                json.dump(new_dataset, fp=f, ensure_ascii=False, indent=4)
        X, Y = obtain_data(pcap_path, samples, features, dataset_save_path)
        return X,Y

    dataset = {}
    
    label_name_list = []

    session_pcap_path  = {}

    for parent, dirs, files in os.walk(pcap_path):
        if label_name_list == []:
            label_name_list.extend(dirs)

        tls13 = 0
        if tls13:
            record_file = os.path.join(BASE_PATH, "results/picked_file_record")
            target_path = os.path.join(BASE_PATH, "results/packet_splitcap/")
            if not os.path.getsize(target_path):
                with open(record_file, 'r') as f:
                    record_files = f.read().split('\n')
                for file in record_files[:-2]:
                    current_path = target_path + file.split('\\')[5]
                    new_name = '_'.join(file.split('\\')[6:])
                    if not os.path.exists(current_path):
                        os.mkdir(current_path)
                    shutil.copyfile(file, os.path.join(current_path, new_name))

        for dir in label_name_list:
            for p,dd,ff in os.walk(os.path.join(parent, dir)):
                if splitcap:
                    for file in ff:
                        session_path = split_cap(pcap_path, os.path.join(p, file), file.split(".")[-2], dir, dataset_level=dataset_level)
                    session_pcap_path[dir] = os.path.join(DATASET_BASE, "splitcap", dir)
                else:
                    session_pcap_path[dir] = os.path.join(pcap_path, dir)
        break

    label_id = {}
    for index in range(len(label_name_list)):
        label_id[label_name_list[index]] = index

    r_file_record = []
    print("\nBegin to generate features.")

    label_count = 0
    for key in tqdm.tqdm(session_pcap_path.keys()):

        if dataset_level == "flow":
            if splitcap:
                for p, d, f in os.walk(session_pcap_path[key]):
                    for file in f:
                        file_size = float(size_format(os.path.getsize(os.path.join(p, file))))
                        # 2KB
                        if file_size < 5:
                            os.remove(os.path.join(p, file))
                            print("remove sample: %s for its size is less than 5 KB." % (os.path.join(p, file)))

            if label_id[key] not in dataset:
                dataset[label_id[key]] = {
                    "samples": 0,
                    "payload": {},
                    "length": {},
                    "time": {},
                    "direction": {},
                    "message_type": {}
                }
        elif dataset_level == "packet":
            if splitcap:# not splitcap
                for p, d, f in os.walk(session_pcap_path[key]):
                    for file in f:
                        current_file = os.path.join(p, file)
                        if not os.path.getsize(current_file):
                            os.remove(current_file)
                            print("current pcap %s is 0KB and delete"%current_file)
                        else:
                            current_packet = scapy.rdpcap(current_file)
                            file_size = float(size_format(os.path.getsize(current_file)))
                            try:
                                if 'TCP' in str(current_packet.res):
                                    # 0.12KB
                                    if file_size < 0.14:
                                        os.remove(current_file)
                                        print("remove TCP sample: %s for its size is less than 0.14KB." % (
                                                    current_file))
                                elif 'UDP' in str(current_packet.res):
                                    if file_size < 0.1:
                                        os.remove(current_file)
                                        print("remove UDP sample: %s for its size is less than 0.1KB." % (
                                                    current_file))
                            except Exception as e:
                                print("error in data_generation 611: scapy read pcap and analyse error")
                                os.remove(current_file)
                                print("remove packet sample: %s for reading error." % (current_file))
            if label_id[key] not in dataset:
                dataset[label_id[key]] = {
                    "samples": 0,
                    "payload": {}
                }
        if splitcap:
            continue

        target_all_files = [os.path.join(x[0], y) for x in [(p, f) for p, d, f in os.walk(session_pcap_path[key])] for y in x[1]]
        sample_size = min(samples[label_count], len(target_all_files))
        if sample_size == 0:
            print(f"Warning: No files found for label {key}")
            label_count += 1
            continue
        print(f"Sampling {sample_size} files from {len(target_all_files)} available files for label {key}")
        r_files = random.sample(target_all_files, sample_size)
        label_count += 1
        for r_f in r_files:
            if dataset_level == "flow":
                feature_data = get_feature_flow(r_f, payload_len=payload_length, payload_pac=payload_packet)
            elif dataset_level == "packet":
                feature_data = get_feature_packet(r_f, payload_len=payload_length)

            if feature_data == -1:
                continue
            r_file_record.append(r_f)
            dataset[label_id[key]]["samples"] += 1
            if len(dataset[label_id[key]]["payload"].keys()) > 0:
                dataset[label_id[key]]["payload"][str(dataset[label_id[key]]["samples"])] = \
                    feature_data[0]
                if dataset_level == "flow":
                    pass
            else:
                dataset[label_id[key]]["payload"]["1"] = feature_data[0]
                if dataset_level == "flow":
                    pass

    all_data_number = 0
    for index in range(len(label_name_list)):
        print("%s\t%s\t%d"%(label_id[label_name_list[index]], label_name_list[index], dataset[label_id[label_name_list[index]]]["samples"]))
        all_data_number += dataset[label_id[label_name_list[index]]]["samples"]
    print("all\t%d"%(all_data_number))

    with open(os.path.join(dataset_save_path, "picked_file_record"),"w") as p_f:
        for i in r_file_record:
            p_f.write(i)
            p_f.write("\n")
    with open(os.path.join(dataset_save_path, "dataset.json"), "w") as f:
        json.dump(dataset,fp=f,ensure_ascii=False,indent=4)

    X,Y = obtain_data(pcap_path, samples, features, dataset_save_path, json_data = dataset)
    return X,Y

def read_data_from_json(json_data, features, samples):
    X,Y = [], []
    ablation_flag = 0
    for feature_index in range(len(features)):
        x = []
        label_count = 0
        for label in json_data.keys():
            sample_num = json_data[label]["samples"]
            if X == []:
                if not ablation_flag:
                    y = [label] * sample_num
                    Y.append(y)
                else:
                    if sample_num > 1500:
                        y = [label] * 1500
                    else:
                        y = [label] * sample_num
                    Y.append(y)
            if samples[label_count] < sample_num:
                x_label = []
                for sample_index in random.sample(list(json_data[label][features[feature_index]].keys()),1500):
                    x_label.append(json_data[label][features[feature_index]][sample_index])
                x.append(x_label)
            else:
                x_label = []
                for sample_index in json_data[label][features[feature_index]].keys():
                    x_label.append(json_data[label][features[feature_index]][sample_index])
                x.append(x_label)
            label_count += 1
        X.append(x)
    return X,Y

def obtain_data(pcap_path, samples, features, dataset_save_path, json_data = None):
    
    if json_data:
        X,Y = read_data_from_json(json_data,features,samples)
    else:
        print("read dataset from json file.")
        with open(os.path.join(dataset_save_path, "dataset.json"),"r") as f:
            dataset = json.load(f)
        X,Y = read_data_from_json(dataset,features,samples)

    for index in range(len(X)):
        if len(X[index]) != len(Y):
            print("data and labels are not properly associated.")
            print("x:%s\ty:%s"%(len(X[index]),len(Y)))
            return -1
    return X,Y

def combine_dataset_json():
    """Combine multiple dataset JSON files"""
    dataset_name = os.path.join(DATASET_BASE, "splitcap", "dataset-")
    dataset = {}
    progress_num = 8
    
    for i in tqdm.tqdm(range(progress_num), desc="Combining dataset files"):
        dataset_file = f"{dataset_name}{i}.json"
        if not os.path.exists(dataset_file):
            print(f"Warning: Dataset file not found: {dataset_file}")
            continue
            
        with open(dataset_file, "r") as f:
            json_data = json.load(f)
        for key in json_data.keys():
            if i > 1:
                new_key = int(key) + 9*1 + 6*(i-1)
            else:
                new_key = int(key) + 9*i
            if new_key not in dataset:
                dataset[new_key] = json_data[key]
                
    output_file = os.path.join(DATASET_BASE, "splitcap", "dataset.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    print(f"Saving combined dataset to {output_file}")
    with open(output_file, "w") as f:
        json.dump(dataset, fp=f, ensure_ascii=False, indent=4)
    return 0

def pretrain_dataset_generation(pcap_path):
    """Generate pretrain dataset from pcap files"""
    output_split_path = os.path.join(DATASET_BASE, "splitcap")  # Dataset specific splitcap directory
    pcap_output_path = DATASET_BASE
    
    # Create output directories if they don't exist
    os.makedirs(output_split_path, exist_ok=True)
    os.makedirs(pcap_output_path, exist_ok=True)
    
    if not os.listdir(pcap_output_path):
        print("Begin to convert pcapng to pcap.")
        files_to_process = []
        for _parent, _dirs, files in os.walk(pcap_path):
            for file in files:
                if file.endswith('.pcapng') or is_pcap_file(file):
                    files_to_process.append((_parent, file))
        
        for _parent, file in tqdm.tqdm(files_to_process, desc="Converting pcap files"):
            if file.endswith('.pcapng'):
                convert_pcapng_2_pcap(_parent, file, pcap_output_path)
            elif is_pcap_file(file):
                shutil.copy(os.path.join(_parent, file), os.path.join(pcap_output_path, file))
    
    # Split pcap files if needed
    if not os.path.exists(output_split_path) or not os.listdir(output_split_path):
        print("Begin to split pcap as session flows.")
        os.makedirs(output_split_path, exist_ok=True)
        
        pcap_files = []
        for _p, _d, files in os.walk(pcap_output_path):
            for file in files:
                if is_pcap_file(file):
                    pcap_files.append((_p, file))
        
        for _p, file in tqdm.tqdm(pcap_files, desc="Splitting pcap files"):
            if is_pcap_file(file):
                split_cap(output_split_path, os.path.join(_p, file), file)
    
    print("Begin to generate burst dataset.")
    # Create word directory if it doesn't exist
    os.makedirs(WORD_DIR, exist_ok=True)
    
    # burst sample - search in the correct splitcap directory
    burst_files = []
    for _p, _d, files in os.walk(output_split_path):
        for file in files:
            if is_pcap_file(file):
                burst_files.append((_p, file))
    
    print(f"Found {len(burst_files)} files for burst feature generation")
    for _p, file in tqdm.tqdm(burst_files, desc="Generating burst features"):
        get_burst_feature(os.path.join(_p, file), payload_len=64)
    return 0

def size_format(size):
    # 'KB'
    file_size = '%.3f' % float(size/1000)
    return file_size

if __name__ == '__main__':
    # pretrain
    # tls 13 downstream
    #pcap_path, samples, features = "I:\\dataset\\labeled\\", 500, ["payload","length","time","direction","message_type"]
    #X,Y = generation(pcap_path, samples, features, splitcap=False)
    # pretrain data
    pretrain_dataset_generation(PCAP_PATH)
    #print("X:%s\tx:%s\tY:%s"%(len(X),len(X[0]),len(Y)))
    # combine dataset.json
    #combine_dataset_json()
