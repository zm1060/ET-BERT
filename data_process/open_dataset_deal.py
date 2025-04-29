#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import shutil
import subprocess

def fix_dataset(method):
    dataset_path = "F:\\dataset\\cstnet-tls1.3\\"

    comand = "I:\\mergecap.exe -w I:\\dataset\\%s.pcap I:\\%s\\*.pcap"
    for p, d, f in os.walk(dataset_path):
        for label in d:
            if label != "0_merge_datas":
                label_domain = label.split(".")[0]
                print(comand%(label_domain,label))

    return 0

def reverse_dir2file():
    path = "F:\\dataset\\"
    for p, d, f in os.walk(path):
        for file in f:
            shutil.move(p + "\\" + file, path)
    return 0

def dataset_file2dir(pcap_path):
    """Organize pcap files into directories by label"""
    for parent, dirs, files in os.walk(pcap_path):
        for file in files:
            if not file.endswith('.pcap'):
                continue
                
            label_name = file.split('.')[0]
            label_dir = os.path.join(parent, label_name)
            
            # Create label directory if it doesn't exist
            os.makedirs(label_dir, exist_ok=True)
            
            # Move file to its label directory
            src = os.path.join(parent, file)
            dst = os.path.join(label_dir, file)
            try:
                shutil.move(src, dst)
            except Exception as e:
                print(f"Error moving file {src} to {dst}: {str(e)}")
    return 0

def file_2_pcap(source_file, target_file):
    """Convert file to pcap format"""
    try:
        shutil.copy2(source_file, target_file)
        os.rename(target_file, target_file + '.pcap')
    except Exception as e:
        print(f"Error converting file {source_file}: {str(e)}")
    return 0

def clean_pcap(source_file):
    target_file = source_file.replace('.pcap','_clean.pcap')
    clean_protocols = '"not arp and not dns and not stun and not dhcpv6 and not icmpv6 and not icmp and not dhcp and not llmnr and not nbns and not ntp and not igmp and frame.len > 80"'
    cmd = "I:\\tshark.exe -F pcap -r %s -Y %s -w %s"
    command = cmd % (source_file, clean_protocols, target_file)
    os.system(command)
    return 0

def statistic_dataset_sample_count(dataset_path):
    """Count samples in each label directory"""
    dataset_length = []
    labels = []
    
    for parent, dirs, files in os.walk(dataset_path):
        for dir_name in dirs:
            dir_path = os.path.join(parent, dir_name)
            file_count = len([f for f in os.listdir(dir_path) if f.endswith('.pcap')])
            dataset_length.append(file_count)
            labels.append(dir_name)
            
    return dataset_length, labels

if __name__ == '__main__':
    fix_dataset(['method'])
