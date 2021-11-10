import os
import time


def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' + directory)


meter = input('input information : ')
loop = int(input('input loop count : '))
default_channel = 37
for i in range(loop):
    print('iterations : {}'.format(i))
    new_channel = i % 3 + default_channel
    dir_path = './rssi_pack_{}/info_{}'.format(time.strftime('%Y_%m_%d', time.localtime(time.time())), meter)
    createFolder(dir_path)
    try:
        result = os.popen('python3 pol_no_mesh.py --channel {}'.format(new_channel)).read()
    except Exception as e:
        print(e)
        continue
    outer = time.strftime('%Y-%m-%d-%H-%M', time.localtime(time.time()))
    f = open('{}/channel_{}_output_{}_{}.txt'.format(dir_path, new_channel, outer, i), 'w')
    f.write(result)
    print(result)
    f.close()

