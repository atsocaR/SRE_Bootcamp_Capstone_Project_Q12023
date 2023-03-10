
class CidrMaskConvert:
    def cidr_to_mask(self, cidr):
        bits = 0
        for i in range(32 - cidr, 32):
            bits |= (1 << i)
        return bits >> 24, (bits >> 16) & 255, (bits >> 8) & 255, bits & 255

    def mask_to_cidr(self, mask):
        # Convert the mask to a binary string
        binary_str = ''.join([bin(int(x))[2:].zfill(8) for x in mask.split('.')])

        # Count the number of consecutive 1's in the binary string
        cidr = 0
        for char in binary_str:
            if char == '1':
                cidr += 1
            else:
                break

        return cidr


class IpValidate:
    def ipv4_validation(self, ip):

        parts = ip.split('.')

        if len(parts) != 4:
            return False

        for part in parts:
            try:
                num = int(part)
                if not (0 <= num <= 255):
                    return False
            except ValueError:
                return False
        return True
