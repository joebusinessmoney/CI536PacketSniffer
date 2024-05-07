import unittest
from model import Model

class modelUnitTesting(unittest.TestCase):
    def testClearFilter(self):
        model = Model()
        model.filter = "TCP"
        self.assertEqual(model.filter, "TCP", "Filter successfully set")
        model.clearFilter()
        self.assertEqual(model.filter, "", "Filter successfully cleared")

    def testGetPackets(self):
        model = Model()
        model.packets.append("Packet 1")
        self.assertEqual(model.packets, ["Packet 1"], "Packet successfully added")

    def testCreateThread(self):
        model = Model()
        model.sniff("en0")

if __name__ == '__main__':
   unittest.main()