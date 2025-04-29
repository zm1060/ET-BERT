# ET-BERT: 使用预训练Transformer的上下文数据报表示方法用于加密流量分类

<!-- 
[![codebeat badge](https://codebeat.co/badges/f75fab90-6d00-44b4-bb42-d19067400243)](https://codebeat.co/projects/github-com-linwhitehat-et-bert-main) 
![](https://img.shields.io/badge/license-MIT-000000.svg) 
[![arXiv](https://img.shields.io/badge/arXiv-1909.05658-<color>.svg)](https://arxiv.org/abs/2202.06335) 
-->

<p align="center">
  <a href='https://codebeat.co/projects/github-com-linwhitehat-et-bert-main'><img src='https://codebeat.co/badges/f75fab90-6d00-44b4-bb42-d19067400243'></a> 
  <a href=''><img src='https://img.shields.io/badge/license-MIT-000000.svg'></a> 
  <a href='https://arxiv.org/abs/2202.06335'><img src='https://img.shields.io/badge/arXiv-1909.05658-<color>.svg'></a> 
  <a href='https://dl.acm.org/doi/10.1145/3485447.3512217' target='_blank'><img src="https://img.shields.io/badge/WWW'22-Paper-blue"></a>
</p>

**注意:**
- ⭐ **如果您喜欢这个项目,请给个<font color='orange'>星星</font>!** ⭐
- 如果您发现任何<font color='red'>错误</font> / <font color='red'>不当</font> / <font color='red'>过时</font>的内容,请考虑提出issue或PR。

**这是ET-BERT的代码仓库,一个用于加密流量分类的网络流量分类模型。**

ET-BERT是一种从加密流量中学习数据报文上下文关系的方法,可以**直接应用于不同的加密流量场景并准确识别流量类别**。首先,ET-BERT在大规模未标记流量中使用多层注意力机制来学习数据报文间的上下文关系和流量间的传输关系。其次,ET-BERT可以通过对小规模标记加密流量进行微调,应用于特定场景以识别流量类型。

![ET-BERT框架](images/etbert.png)

这项工作发表在*[第31届万维网国际会议](https://www2022.thewebconf.org/)*:
> Xinjie Lin, Gang Xiong, Gaopeng Gou, Zhen Li, Junzheng Shi and Jing Yu. 2022. ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification. In Proceedings of The Web Conference (WWW) 2022, Lyon, France. Association for Computing Machinery.

注:本代码基于[UER-py](https://github.com/dbiir/UER-py)。非常感谢作者们的工作。
<br/>

目录
=================
  * [环境要求](#环境要求)
  * [数据集](#数据集)
  * [使用ET-BERT](#使用ET-BERT)
  * [复现ET-BERT](#复现ET-BERT)
  * [引用](#引用)
  * [联系方式](#联系方式)
<br/>

## 环境要求
* Python: 3.6-3.8 (推荐3.8)
* CUDA: 11.3 或 10.2
* GPU: Tesla V100S 或类似
* torch >= 1.1
* six >= 1.12.0
* scapy == 2.4.4
* numpy == 1.19.2
* shutil, random, json, pickle, binascii, flowcontainer
* argparse
* packaging
* tshark
* [SplitCap](https://www.netresec.com/?page=SplitCap)
* [scikit-learn](https://scikit-learn.org/stable/)
* 如需混合精度训练,需要NVIDIA的apex
* 如需转换预训练模型(与TensorFlow相关),需要TensorFlow
* 如需使用wordpiece模型进行分词,需要[WordPiece](https://github.com/huggingface/tokenizers)
* 如需在序列标注下游任务中使用CRF,需要[pytorch-crf](https://github.com/kmkurn/pytorch-crf)
<br/>

### 环境配置
1. 创建并激活conda环境:
```bash
# 创建Python 3.8环境(推荐)
conda create -n etbert python=3.8
conda activate etbert
```

2. 使用conda安装基础依赖:
```bash
# 首先安装numpy和setuptools
conda install numpy=1.19.2 setuptools

# 安装支持CUDA的PyTorch
# CUDA 11.3 (推荐)
conda install pytorch cudatoolkit=11.3 -c pytorch

# CUDA 10.2
conda install pytorch cudatoolkit=10.2 -c pytorch

# 其他CUDA版本请参考 https://pytorch.org/
```

3. 安装其余依赖:
```bash
# 安装系统开发库(scapy需要)
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install build-essential python3-dev libpcap-dev libc6-dev

# 按特定顺序安装Python依赖
pip install --no-cache-dir tokenizers==0.13.3
pip install -r requirements.txt

# 安装Wireshark/tshark
sudo apt-get install wireshark tshark
```

4. 下载并安装[SplitCap](https://www.netresec.com/?page=SplitCap)用于处理pcap文件。

注意:
- 代码已在Python 3.6-3.8上测试通过
- 虽然原始代码使用CUDA 11.4,但模型兼容其他CUDA版本
- 如遇到兼容性问题,请提出issue
- 对于更新的Python版本(>3.8),可能需要使用更新的包版本
- 建议使用conda安装numpy和PyTorch以避免兼容性问题
- 部分系统依赖需要root/管理员权限
- Windows用户可能需要额外步骤来设置数据包捕获功能
- 如遇到tokenizers问题,尝试重新安装:`pip install --no-cache-dir tokenizers==0.13.3`

## 数据集
真实世界的TLS 1.3数据集收集自2021年3月至7月的中国科技网(CSTNET)。出于隐私考虑,我们只发布了匿名数据(见[CSTNET-TLS 1.3](CSTNET-TLS%201.3/readme.md))。

我们用于对比实验的其他数据集是公开可用的,详见[论文](https://arxiv.org/abs/2202.06335)。如果您想使用自己的数据,请检查数据格式是否与`datasets/cstnet-tls1.3/`相同,并在`data_process/`中指定数据路径。

<br/>

## 使用ET-BERT
您现在可以直接通过预训练[模型](https://drive.google.com/file/d/1r1yE34dU2W8zSqx1FkB8gCWri4DQWVtE/view?usp=sharing)使用ET-BERT,或通过以下方式下载:
```
wget -O pretrained_model.bin https://drive.google.com/file/d/1r1yE34dU2W8zSqx1FkB8gCWri4DQWVtE/view?usp=sharing
```

获得预训练模型后,可以通过对带标签的网络流量进行包级别的微调,将ET-BERT应用到特定任务:
```
PYTHONPATH=. python3 fine-tuning/run_classifier.py --pretrained_model_path models/pre-trained_model.bin \
                                   --vocab_path models/encryptd_vocab.txt \
                                   --train_path datasets/CSTNET-TLS1.3/train_dataset.tsv \
                                   --dev_path datasets/CSTNET-TLS1.3/valid_dataset.tsv \
                                   --test_path datasets/CSTNET-TLS1.3/test_dataset.tsv \
                                   --epochs_num 10 --batch_size 32 --embedding word_pos_seg \
                                   --encoder transformer --mask fully_visible \
                                   --seq_length 128 --learning_rate 2e-5
```

微调后的分类器模型默认保存路径为`models/finetuned_model.bin`。然后您可以使用微调后的模型进行推理:
```
PYTHONPATH=. python3 inference/run_classifier_infer.py --load_model_path models/finetuned_model.bin \
                                          --vocab_path models/encryptd_vocab.txt \
                                          --test_path datasets/CSTNET-TLS1.3/nolabel_test_dataset.tsv \
                                          --prediction_path datasets/CSTNET-TLS1.3/prediction.tsv \
                                          --labels_num 2 \
                                          --embedding word_pos_seg --encoder transformer --mask fully_visible
```
<br/>

## 复现ET-BERT
### 预处理
要在网络流量数据上复现预训练ET-BERT的步骤,请按以下步骤操作:
 1. 运行`vocab_process/main.py`生成加密流量语料库,或直接使用`corpora/`中生成的语料库。注意需要修改文件顶部的文件路径和一些配置。
 2. 运行`main/preprocess.py`预处理加密流量突发语料库。
    ```
PYTHONPATH=. python3 preprocess.py --corpus_path corpora/encrypted_traffic_burst.txt \
                             --vocab_path models/encryptd_vocab.txt \
                             --dataset_path dataset.pt --processes_num 8 --target bert
    ```
 3. 如果有需要处理的pcap格式数据集,运行`data_process/main.py`生成下游任务的数据。这个过程包括两个步骤。首先是通过在`datasets/main.py:54`设置`splitcap=True`来分割pcap文件并保存为`npy`数据集。然后是生成微调数据。如果您使用共享的数据集,则需要在`dataset_save_path`下创建名为`dataset`的文件夹并将数据集复制到这里。

### 预训练
要复现在标记数据上微调ET-BERT的步骤,运行`pretrain.py`进行预训练。如果想在已预训练的模型基础上继续训练,可以增加参数`--pretrained_model_path`。
```
PYTHONPATH=. python3 pre-training/pretrain.py --dataset_path dataset.pt --vocab_path models/encryptd_vocab.txt \
                    --output_model_path models/pre-trained_model.bin \
                    --world_size 8 --gpu_ranks 0 1 2 3 4 5 6 7 \
                    --total_steps 500000 --save_checkpoint_steps 10000 --batch_size 32 \
                    --embedding word_pos_seg --encoder transformer --mask fully_visible --target bert
```

### 下游任务微调
要查看如何将ET-BERT用于加密流量分类任务的示例,请参考[使用ET-BERT](#使用ET-BERT)部分和`fine-tuning`文件夹中的`run_classifier.py`脚本。

注意:您需要修改程序中的路径。
<br/>

## 引用
#### 如果您在学术工作中使用了ET-BERT的工作(如预训练模型),请引用发表在WWW 2022的[论文](https://dl.acm.org/doi/10.1145/3485447.3512217):

```
@inproceedings{lin2022etbert,
  author    = {Xinjie Lin and
               Gang Xiong and
               Gaopeng Gou and
               Zhen Li and
               Junzheng Shi and
               Jing Yu},
  title     = {{ET-BERT:} {A} Contextualized Datagram Representation with Pre-training
               Transformers for Encrypted Traffic Classification},
  booktitle = {{WWW} '22: The {ACM} Web Conference 2022, Virtual Event, Lyon, France,
               April 25 - 29, 2022},
  pages     = {633--642},
  publisher = {{ACM}},
  year      = {2022}
}
```

<br/>

## 联系方式
如有任何问题,请在Github上提出issue。欢迎讨论新的想法、技术和改进!
