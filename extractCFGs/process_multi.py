import os
import sys
import shutil
from multiprocessing import Process, Queue, Lock
from utils.listdir import list_all_files

Process_num = 120
Result_dir = 'results'

def processing(bin_file_list, file_total_num):
    for binFile in bin_file_list:
        os.system('python3 extrfiles.py -f %s -O %s>/dev/null 2>&1'%(binFile, Result_dir))
        mutex.acquire()
        suc = 0
        q.put(binFile)
        processed_num = q.qsize()
        targetYaml = os.path.splitext(os.path.split(binFile)[-1])[0] + '.yaml'
        if os.path.exists(os.path.join(Result_dir, targetYaml)):
            suc = 1
        print('Processing %d / %d  %s  suc: %d'%(processed_num, file_total_num, binFile, suc))
        mutex.release()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Error: Please input the target directory.')
    elif len(sys.argv) > 2:
        print('Error: Too many params.')
    else:
        targetDir = sys.argv[1]
        if not os.path.exists(targetDir):
            print('Error: The input directory is not exists.')
        elif not os.path.isdir(targetDir):
            print('Error: The input is not a directory.')
        else:
            if os.path.exists(Result_dir):
                shutil.rmtree(Result_dir)
            global q
            q = Queue()
            global mutex
            mutex = Lock()

            fileList = []
            for binFile in list_all_files(targetDir):
                if not os.path.split(binFile)[-1].startswith('.'):
                    fileList.append(binFile)

            fileNum = len(fileList)
            step = int(fileNum / Process_num)

            for i in range(Process_num - 1):
                proc = Process(target=processing, args=(fileList[i * step : (i + 1) * step], fileNum, ))
                proc.start()
            proc = Process(target=processing, args=(fileList[(Process_num - 1) * step : ], fileNum, ))
            proc.start()