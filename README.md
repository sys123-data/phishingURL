# phishingURL



- pip3 freeze > requirements.txt  # Python3
- pip freeze > requirements.txt  # Python2
- pip install -r requirements.txt --no-index --find-links file:///tmp/packages


for notebook copy `urldata.csv` and `ai.ipynb` in a folder and type the commands:
```
conda create -n automl
conda activate automl
conda install notebook
conda install -c conda-forge pandas
conda install -c conda-forge seaborn
conda install -c conda-forge scikit-learn
conda install -c conda-forge xgboost
conda install -c conda-forge keras
conda install -c anaconda tensorflow
conda install gxx_linux-64 gcc_linux-64 swig
pip install auto-sklearn==0.13
pip install 'scipy==1.7.0'

```