# GCloud UDP fingerprint fiter solution with XDP eBPF

An step by step guide to build up a high performance UDP fingerprint filter solution. 

* [GCloud UDP fingerprint filter solution](#gcloud-udp-fingerprint-fiter-solution-with-xdp-ebpf)
* [Overview](#overview)
  * [Solution Background](#solution-background)
  * [Architecture](#solution-architecture)
  * [Design Consideration](#design-consideration)
* [Get Started](#get-started)
## Overview
Some game genres has low latency request, so game developer has started build up game transport stack based on UDP protocol. UDP is stateless transport protocal which is vulnerable to DDoS attack. When the Game server under attack, it will exhaust all the resource of the server, then all the users serve on it will be impacted. In the industry UDP DDoS protection is hot topic, one of the effective method is token authorization, game delveloper embed authorized access token in UDP payload, anti-DDoS facility will check the token and drop the packet with unauthorized token. Some Cloud Vendor/CDN Vendor has provided this capability on its network security product. When Build self performance is a key blocker, [eBPF XDP](https://docs.cilium.io/en/stable/concepts/ebpf/intro/) is a good candidate to work as token filter with high performance. This repo target is to help you getting start to build up a eBPF XDP based UDP filter Solution on GCP(Google Cloud Platform), you can also folk this architucture on other environment.  

### Solution Background
In the demo environment, we will using GCE(Google Compute Engine) to build up a gateway tier sit between Game Server and Client. The gateway tier will host the eBPF XDP program with UDP token filter function, only the packet with anthorized token is forward to the Game Server. In the XDP program, it hosts a [eBPF MAP](https://www.slideshare.net/suselab/ebpf-maps-101) that store the forwarding rule, one unique token mapping to a game server. There also has a userspace controller code which used to program the forwarding rule in the eBPF MAP. To better optimized the performance of the XDP program, on GCP it leverage the Network Loadbalancer's [DSR(direct server return)](https://cloud.google.com/load-balancing/docs/network) capability, the return traffic can go back to client directly bypassing the gateway. 

### Architecture
This repo will give a tourial to setup a UDP gateway deployment as below architecture. Game Server will expose Internet access using GCP Cloud Network Load Balancer(NLB), with NLB XDP Gateway instance can scale-out, client traffic can distribute across the instance in the XDP Gateway Instance Group.

<img src="./img/xdpgateway_architecture.png" alt="XDP Gateway GCP architecture">

The packet process lifecycle is as below, client connect to the NLB public ip, then the client ingress packet is directed to the XDP Gateway Instance Group, the XDP eBPF program filter the client packet based on the UDP fingerprint in the packet, if the packet has no valid UDP fingerprint it will be dropped, the packet with valid UDP fingerprint will be redirected to the Game Serer. The Game Server Redirection forwarding logic is based on the UDP fingerprint(token) mapping, by looking up the mapping the packet's destination ip is translated to the Game Server's VPC(Virtual Private Network) internal network IP. When the packet arrive on the Game Server, Game Server can handle the packet with Game Logic. For the egress packet(return packet from Game Server), to leverage the DSR(direct server return, bypassing the Network Load Balancer) capability, on Game Server developer can setup a iptables to translate the ingress packet's destination ip address to NLB's public ip, or in the socket devlopment code, parse the egress socket's source ip to NLB's public ip.

<img src="./img/xdpgateway_packetlife.png" alt="XDP Gateway Pakcet Process lifecycle">

### Design Consideration
In the design there are some key points to achieve the high performance and scalability.
#### Performance Consideration
The solution is targeted to achieve high performance with cost-optimized instance selection rule. The overall forwarding performance is depend on the instance type(GCE instance type) and instance number. Also combined with the ingress bandwidth limit on [Google Cloud VM](https://cloud.google.com/compute/docs/network-bandwidth#summary-table)(1.8M pps per instance, 20Gbps per instance), so with suitable size instance(instance with enough vcores) can achieve this bandwidth limit. There has some performance benchmark list here for customer to select their instance type. In general, instance with more vcores get more forwarding performance, XDP eBPF leverage Multi Queue process logic, GCE instance with more vcores get more [Receive/Transmit queues](https://cloud.google.com/compute/docs/network-bandwidth#rx-tx). And then for the XDP eBPF program running in the instance, there has diff [deployment mode](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/)(generic, native, offloaded), native and offloaded mode has better performance compared to native, but it needs the nic driver to support this mode, currently GCP instance not support native and offloaded mode, so when GCP instance is ready for native mode, customer can migrate to native mode to get more performance benifit. Below is per vcore pps and bandwidth benchmark.

#### Scalability Consideration
The solution is using scale-out model to achieve high performance, the XDP Gateway Instance Group and Game Server Instance Group are configed as backend of Cloud Network Load Balancer, so the maximum instance it can support depend on the maximum instance per instance group and maximum instance group that Cloud Network Load Balancer support, currently [GCP support maximum 2000 backend endpoint](https://cloud.google.com/load-balancing/docs/quotas#vms_per_instance_group) under a instance group, and maximum [50 instance groups](https://cloud.google.com/load-balancing/docs/quotas#backends) under a single Cloud Network Load Balancer. 

## Get Started
### Prepare the Google Cloud environment
#### 1. Create the virtual private network

#### 2. Create XDP Gateway and XDP Gateway instance group

#### 3. Create Game Server and Game Server instance group

#### 4. Create Cloud Network Load Balancer, XDP Gateway Instance Group as Active Backend, Game Server Instance Group as Failover Backend.

### Deploy the XDP eBPF program on XDP Gateway Instance

### Deploy the XDP eBPF controller program on XDP Gateway Instance

### Connectivity Test with NC tool