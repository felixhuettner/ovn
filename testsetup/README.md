# Testimplementation

I first want to shortly share the setup i implemented this on:
The testsetup consists of 3 ovn nodes. One representing a compute node
while two others serve as gateways. The gateways also each have a
point-ot-point interface to an additional machine that represents a
leaf-spine architecture using network namespaces and static routes.

For the OVN northbound content we have:
* a normal neutron project setup with a:
* LSP for a VM (LSP-VM)
   * LS for the network (LS-internal)
   * LR for the router (R1)
   * LSP to the router (LSP-internal-R1)
   * LRP to the network (LRP-R1-internal)
   * a nat rule on R1 representing a floating ip
* The router R1 has an LRP (LRP-R1-public) with a ha_chassis_group
  configured to point to both gateways with different priorities
* There is an integration LR (public) that serves as the integration
  point of different projects. It replaces the LS normally used for
  this.
* The LR public has options:chassis configured to "gtw01,gtw02" (therby
  making it an l3gateway)
* LR public has an LRP (LRP-public-R1)
* The LRPs LRP-public-R1 and LRP-R1-public are configured as each others
  peers
* There is a logical switch (LS-public-for-real)
* LS-public-for-real has a LSP (physnet) of type localnet and
  network_name set
* LR public has an LRP (LRP-public-for-real)
* LS-public-for-real has a LSP (LSP-public)
* LSP-public and LRP-public-for-real are connected

This setup contains two things that are currently not possible:
1. l3gateways can not be bound by more than 1 chassis
2. l3gateway lrps can not be directly connected to a distributed gateway port                                                                                                                                                                                                                                                                                                              
