from build_dataset import build
from train_text import train
from train_urls import train as url_train
if __name__=='__main__':
    build()
    train()
    url_train()
    print('Done. Start web app with: python run.py')
