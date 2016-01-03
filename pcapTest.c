#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	// 查看网卡，返回默认使用的网卡的名字
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}
	printf("Device: %s\n", dev);

	pcap_t *handle;

	/*
	 *
	 * open device for sniffing
	 * pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
	 *
	 * 第一个参数　是网卡设备名字(pcap_lookupdev() 返回的字符串)
	 * 第二个参数，　设置pcap 抓取的网络包的最大字节数
	 * 第三个参数，　true，设置网卡的混杂模式(promiscuous mode)－－－监听能收到所有包（不仅是本机的）
	 *　			　　false,　可能会是非混杂模式
	 * 第四个参数，　read time out in milliseconds -- 个人理解，　等待to_ms时间pcap才会返回抓取的包
	 * 第五个参数，　store any error messages
	 *
	 * 返回　打开的设备的句柄
	 * In standard, non-promiscuous sniffing,
	 * a host is sniffing only traffic that is directly related to it.
	 * Only traffic to, from, or routed through the host will be
	 * picked up by the sniffer. Promiscuous mode, on the other hand,
	 * sniffs all traffic on the wire.
	 *
	 * */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr,
				"Device %s doesn't provide Ethernet headers - not supported\n",
				dev);
		return (2);
	} else {
		fprintf(stdout, "support ethernet.\n");
	}

	return (0);
}

