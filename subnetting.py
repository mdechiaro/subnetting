#!/usr/bin/python
# vim: ts=4 sw=4 et
"""Simple Subnetting Class."""
class Subnetting(object):
    """ This class with handle easy subnetting."""
    def __init__(self):
        pass

    @staticmethod
    def magic_number(netmask):
        """
        Returns the magic number for subnetting. The magic number is calculated
        by finding the first octet that does not equal 255, and substracting
        256 from it. It also returns the octet that matched.

        Args:
            netmask (str): The netmask in string format

        Returns:
            tuple (int): A tuple containing the magic number and matching octet
        """
        for num, octet in enumerate(netmask.split('.')):
            if int(octet) != 255:
                return (256 - int(octet), num)

    def cidr2netmask(self, cidr):
        """
        Converts a cidr notation into a netmask. It converts the value into ones
        and then pads the rest with zeroes to make a 32 bit string.

        Args:
            cidr (int): A cidr notation of a netmask

        Returns:
            netmask (str): A netmask in string format
        """
        binary = ''
        if int(cidr) <= 32:
            for dummy in range(int(cidr)):
                binary += '1'

            return self.bin2ipaddr(binary.ljust(32, '0'))

    def netmask2cidr(self, netmask):
        """
        Converts netmask to cidr notation. It converts the value to binary
        and counts the number of ones.

        Args:
            netmask (str): The netmask in string format

        Returns:
            cidr (int): The cidr notation for a given netmask
        """
        count = 0
        for num in self.ipaddr2bin(netmask):
            if int(num) == 1:
                count += 1

        return count

    @staticmethod
    def ipaddr2bin(ipaddr, fmt=''):
        """
        Returns ipaddr in binary format.

        Args:
            ipaddr (str): ip address in string format
            fmt (str): A format string for joining the ip octets

        Returns:
            binary (str): ip address converted to binary

        Raises:
           ValueError if format is invalid
        """
        try:
            return fmt.join(format(int(x), '08b') for x in ipaddr.split('.'))
        except ValueError as err:
            return err.message

    @staticmethod
    def bin2ipaddr(binary):
        """
        Converts ip address in binary to string

        Args:
            binary (str): ip address converted to binary

        Returns:
            ipaddr (str): ip address in string format

        Raises:
           ValueError if format is invalid
        """
        # split the binary into 8 bit segments
        octets = [binary[i:i+8] for i in range(0, len(binary), 8)]

        try:
            return '.'.join(str(int(octet, 2)) for octet in octets)
        except ValueError as err:
            return err.message

    def network(self, ipaddr):
        """
        Returns network of given ip address and netmask

        Args:
            ipaddr (str): An ip address and netmask
                          format: 1.2.3.4/24 or 1.2.3.4/255.255.255.0
        Returns:
            broadcast (str): A broadcast address
        """
        addr, netmask = ipaddr.split('/')
        # cidr notation
        if len(str(netmask)) <= 2:
            bin_netmask = self.cidr2netmask(netmask)
            bin_netmask = self.ipaddr2bin(bin_netmask)
            bin_ipaddr = self.ipaddr2bin(addr)
            network = []
        # netmask
        else:
            bin_netmask = self.ipaddr2bin(netmask)
            bin_ipaddr = self.ipaddr2bin(addr)
            network = []

        # bitwise AND
        for ipaddr_num, netmask_num in zip(bin_ipaddr, bin_netmask):
            network.append(int(ipaddr_num) & int(netmask_num))

        return self.bin2ipaddr(''.join(str(item) for item in network))

    def broadcast(self, ipaddr):
        """
        Returns broadcast of given ip address and netmask

        Args:
            ipaddr (str): An ip address and netmask
                          format: 1.2.3.4/24 or 1.2.3.4/255.255.255.0
        Returns:
            broadcast (str): A broadcast address
        """
        addr, netmask = ipaddr.split('/')
        # cidr notation
        if len(str(netmask)) <= 2:
            bin_netmask = self.cidr2netmask(netmask)
            bin_netmask = self.ipaddr2bin(bin_netmask)
            # need to inverse the bits for broadcast
            bin_netmask = ''.join('1' if x == '0' else '0' for x in bin_netmask)
            bin_ipaddr = self.ipaddr2bin(addr)
            network = []
        # netmask
        else:
            bin_netmask = self.ipaddr2bin(netmask)
            # need to inverse the bits for broadcast
            bin_netmask = ''.join('1' if x == '0' else '0' for x in bin_netmask)
            bin_ipaddr = self.ipaddr2bin(addr)
            network = []

        # bitwise OR
        for ipaddr_num, netmask_num in zip(bin_ipaddr, bin_netmask):
            network.append(int(ipaddr_num) | int(netmask_num))

        return self.bin2ipaddr(''.join(str(item) for item in network))

    def isipaddrnet(self, ipaddr, network):
        """
        Compares the network and netmask with the given ip address and netmask.
        It returns True if both the network and broadcast addresses match.

        Args:
            ipaddr (str): An ip address and netmask
                          format: 1.2.3.4/24 or 1.2.3.4/255.255.255.0
            network (str): An ip address and netmask
                          format: 1.2.3.4/24 or 1.2.3.4/255.255.255.0
        Returns:
            bool: True if match or None
        """
        ipaddr_net = self.network(ipaddr)
        network_net = self.network(network)
        ipaddr_bcast = self.broadcast(ipaddr)
        network_bcast = self.broadcast(network)

        if ipaddr_net == network_net and ipaddr_bcast == network_bcast:
            return True
