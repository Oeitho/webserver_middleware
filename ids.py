from Kitsune import Kitsune
import numpy as np
import time

class IntrusionDetector(object):
    def __init__(self):
        path = "../pcap2/packets.pcap" #the pcap, pcapng, or tsv file to process.
        packet_limit = 5000 #the number of packets to process
        # KitNET params:
        maxAE = 10 #maximum size for any autoencoder in the ensemble layer
        FMgrace = 5000 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
        ADgrace = 40000 #the number of instances used to train the anomaly detector (ensemble itself)
        # Build Kitsune
        self.kitsune = Kitsune(path,packet_limit,maxAE,FMgrace,ADgrace)
        self.RMSE = []
        i = 0
        while True:
            i+=1
            if i % 1000 == 0:
                print(i)
            rmse = self.kitsune.proc_next_packet()
            if rmse == -1:
                break
            self.RMSE.append(rmse)
    
    def packet_rmse(self, packet):
        return self.kitsune.process_packet(packet)

if __name__ == '__main__':
    intrusion_detector = IntrusionDetector()
