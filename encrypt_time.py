import os
import time
import json

# pip install matplotlib
import matplotlib.pyplot as plt
# pip install pycryptodome
from Crypto import Random
from Crypto.Cipher import AES, DES, DES3, DESX


def time_encrypt(infile):
    """
    find the times for encrypting a file with various methods
    :param infile: name of the file being encrypted
    :return: None
    """
    rtn_dict = dict()
    with open(infile) as f:
        data = f.read().encode()

    # DES
    print('\tStarting DES...')
    encryptor = DES.new(Random.get_random_bytes(8), DES.MODE_ECB)
    start = time.time()
    encryptor.encrypt(data)
    end = time.time()
    rtn_dict['DES'] = end - start

    # 3DES
    print('\tStarting 3DES...')
    while True:
        try:
            DES3_key = DES3.adjust_key_parity(Random.get_random_bytes(24))
            break
        except ValueError:
            pass
    encryptor = DES3.new(DES3_key, DES3.MODE_ECB)
    start = time.time()
    encryptor.encrypt(data)
    end = time.time()
    rtn_dict['3DES'] = end - start

    # DESX
    print('\tStarting DESX...')
    encryptor = DESX.new(Random.get_random_bytes(24), DESX.MODE_ECB)
    encryptor.encrypt(data)
    end = time.time()
    rtn_dict['DESX'] = end - start

    # AES
    print('\tStarting AES...')
    encryptor = AES.new(Random.get_random_bytes(32), AES.MODE_ECB)
    start = time.time()
    encryptor.encrypt(data)
    end = time.time()
    rtn_dict['AES'] = end - start

    return rtn_dict


def main():
    sizes = [s for s in range(1024**3, 1024, -64 * (1024**2))]
    # sizes = []

    if os.path.exists('time_output.json'):
        with open('time_output.json', 'r') as f:
            sizes_dict = json.loads(f.read())
    else:
        sizes_dict = dict()

    for size in sizes:
        if str(size) not in sizes_dict:
            # check if you need to generate a file to encrypt
            path = f'files/size_{size}_bytes.0'
            if not os.path.exists(path):
                with open(path, 'wb') as out:
                    out.seek(size - 1)
                    out.write(b'\0')

            print(f'starting {size}...')
            times = time_encrypt(path)
            sizes_dict[size] = times
            with open('time_output.json', 'w') as f:
                json.dump(sizes_dict, f)

    algos = ['DES', '3DES', 'DESX', 'AES']
    times_dict = {a: [] for a in algos}
    sorted_sizes = sorted(int(s) for s in sizes_dict)
    for size in sorted_sizes:
        for algo in algos:
            times_dict[algo].append(sizes_dict[str(size)][algo])

    for i in range(len(algos)):
        cur_algos = algos[:i + 1]
        plt.xlabel('File size (bytes)')
        plt.ylabel('Time (seconds)')
        plt.title('Encryption Size vs. Time of Various Algorithms')
        for algo in cur_algos:
            plt.plot(sorted_sizes, times_dict[algo], label=algo)
        plt.legend()
        plt.show()

    plt.xlabel('File size (bytes)')
    plt.ylabel('Time (seconds)')
    plt.title('Encryption Size vs. Time of AES')
    plt.plot(sorted_sizes, times_dict['AES'], label='AES')
    plt.legend()
    plt.show()


if __name__ == '__main__':
    main()
