# ET-BERT 运行指南

## 环境要求
- Python: 3.6-3.8 (推荐3.8)
- CUDA: 11.3 或 10.2
- GPU: Tesla V100S 或类似
- PyTorch >= 1.1
- 其他依赖：
  - scapy == 2.4.4
  - numpy == 1.19.2
  - tokenizers == 0.13.3
  - six >= 1.12.0
  - tshark
  - SplitCap

### 环境配置
1. 创建并激活conda环境：
```bash
conda create -n etbert python=3.8
conda activate etbert
```

2. 安装基础依赖：
```bash
# 安装numpy和setuptools
conda install numpy=1.19.2 setuptools

# 安装PyTorch (CUDA 11.3)
conda install pytorch cudatoolkit=11.3 -c pytorch
```

3. 安装其他依赖：
```bash
# 安装系统依赖
sudo apt-get update
sudo apt-get install build-essential python3-dev libpcap-dev libc6-dev wireshark tshark

# 安装Python依赖
pip install --no-cache-dir tokenizers==0.13.3
pip install -r requirements.txt
```

## 项目结构
```
ET-BERT/
├── datasets/
│   └── CSTNet-TLS1.3/    # 数据集目录
│       ├── pcap/         # 原始pcap文件
│       ├── splitcap/     # 处理后的文件
│       └── results/      # 结果文件
├── corpora/              # 预训练语料库
├── models/               # 模型存储
├── data_process/         # 数据预处理脚本
├── pre-training/         # 预训练相关脚本
├── fine-tuning/         # 微调相关脚本
└── inference/           # 推理相关脚本
```

## 完整运行流程

### 1. 数据预处理
#### 1.1 生成语料库
```bash
python3 vocab_process/main.py
```
生成的语料库在`corpora/`目录下
或直接使用 `corpora/` 中的预生成语料库

#### 1.2 预处理语料库
```bash
PYTHONPATH=. python3 preprocess.py \
    --corpus_path corpora/encrypted_traffic_burst.txt \
    --vocab_path models/encryptd_vocab.txt \
    --dataset_path dataset.pt \
    --processes_num 8 \
    --target bert
```

#### 1.3 处理pcap文件
```bash
cd data_process
python dataset_generation.py  # 处理原始pcap文件并生成数据集
```

### 2. 模型预训练
如果不使用预训练模型，需要先进行预训练：
```bash
PYTHONPATH=. python3 pre-training/pretrain.py \
    --dataset_path dataset.pt \
    --vocab_path models/encryptd_vocab.txt \
    --output_model_path models/pre-trained_model.bin \
    --world_size 8 \
    --gpu_ranks 0 1 2 3 4 5 6 7 \
    --total_steps 500000 \
    --save_checkpoint_steps 10000 \
    --batch_size 32 \
    --embedding word_pos_seg \
    --encoder transformer \
    --mask fully_visible \
    --target bert
```

也可以下载预训练模型：
```bash
wget -O models/pretrained_model.bin https://drive.google.com/file/d/1r1yE34dU2W8zSqx1FkB8gCWri4DQWVtE/view?usp=sharing
```

### 3. 模型微调
使用预训练模型进行微调：
```bash
PYTHONPATH=. python3 fine-tuning/run_classifier.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --vocab_path models/encryptd_vocab.txt \
    --train_path datasets/CSTNET-TLS1.3/train_dataset.tsv \
    --dev_path datasets/CSTNET-TLS1.3/valid_dataset.tsv \
    --test_path datasets/CSTNET-TLS1.3/test_dataset.tsv \
    --epochs_num 10 \
    --batch_size 32 \
    --embedding word_pos_seg \
    --encoder transformer \
    --mask fully_visible \
    --seq_length 128 \
    --learning_rate 2e-5
```

### 4. 模型推理
使用微调后的模型进行推理：
```bash
PYTHONPATH=. python3 inference/run_classifier_infer.py \
    --load_model_path models/finetuned_model.bin \
    --vocab_path models/encryptd_vocab.txt \
    --test_path datasets/CSTNET-TLS1.3/nolabel_test_dataset.tsv \
    --prediction_path datasets/CSTNET-TLS1.3/prediction.tsv \
    --labels_num 120 \
    --embedding word_pos_seg \
    --encoder transformer \
    --mask fully_visible
```

### 5. 结果查看
- 训练过程中的混淆矩阵：`datasets/CSTNet-TLS1.3/results/confusion_matrix.txt`
- 预测结果：在指定的 `prediction_path`

## 注意事项
1. 确保所有路径正确配置
2. 数据预处理前确保 SplitCap.exe 可用
3. 预训练需要较大的计算资源，建议使用多GPU
4. 训练前确保显存足够
5. 推理时标签数量要与训练时一致

## 常见问题
1. 如果出现 "No such file or directory" 错误，请检查相关目录是否存在
2. 如果出现显存不足，可以：
   - 减小 batch_size
   - 减少 GPU 数量（修改 world_size 和 gpu_ranks）
3. 如果需要调整采样数量，可以在 `main.py` 中修改 `DEFAULT_SAMPLES`
4. 预训练时如果GPU数量不足，可以相应调整 world_size 和 gpu_ranks

## 参考
- 更多详细配置请参考代码中的注释
- 完整文档请参考 README.md
- 如有问题请提交 Issue
