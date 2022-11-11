from enum import Enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class PacketType(Enum):
    GFSK = 0x00
    LORA = 0x01
    RANGING = 0x02
    FLRC = 0x03
    BLE = 0x04
    UNDEFINED = 0xFF

class sx128x_in(HighLevelAnalyzer):
    result_types = {
        "SpiTransaction": {
            "format": "{{data.dataout}}"
        },
        "SpiTransactionError": {
            "format": "ERROR: {{data.error_info}}",
        }
    }
    
    packetType: PacketType

    def __init__(self):
        # Holds the individual SPI result frames that make up the transaction
        self.frames = []

        # Whether SPI is currently enabled
        self.spi_enable = False

        # Start time of the transaction - equivalent to the start time of the "Enable" frame
        self.transaction_start_time = None

        # Whether there was an error.
        self.error = False
        
        # Initialize packetType to undefined
        self.packetType = PacketType.UNDEFINED

    def handle_enable(self, frame: AnalyzerFrame):
        self.frames = []
        self.spi_enable = True
        self.error = False
        self.transaction_start_time = frame.start_time

    def reset(self):
        self.frames = []
        self.spi_enable = False
        self.error = False
        self.transaction_start_time = None

    def is_valid_transaction(self) -> bool:
        return self.spi_enable and (not self.error) and (self.transaction_start_time is not None)

    def handle_result(self, frame):
        if self.spi_enable:
            self.frames.append(frame)

    def get_frame_data(self) -> dict:
        miso = bytearray()
        mosi = bytearray()

        for frame in self.frames:
            miso += frame.data["miso"]
            mosi += frame.data["mosi"]

        if len(mosi) > 0:
            # 0x00 = NOP
            if len(mosi) >= 1 and mosi[0] == 0x00:
                return { "dataout": "NOP" }

            # 0x03 = GetPacketType()
            if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x03:
                pType = "UNDEFINED"
                if miso[2] == PacketType.GFSK:
                    self.packetType = PacketType.GFSK
                    pType = "GFSK"
                if miso[2] == PacketType.LORA:
                    self.packetType = PacketType.LORA
                    pType = "LORA"
                if miso[2] == PacketType.RANGING:
                    self.packetType = PacketType.RANGING
                    pType = "RANGING"
                if miso[2] == PacketType.FLRC:
                    self.packetType = PacketType.FLRC
                    pType = "FLRC"
                if miso[2] == PacketType.BLE:
                    self.packetType = PacketType.BLE
                    pType = "BLE"
                if pType == "UNDEFINED":
                    self.packetType = PacketType.UNDEFINED
                return { "dataout": "GetPacketType()=" + pType }
            
            # 0x15 = GetIrqStatus()
            if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x15:
                irqStatus = miso[2]*256 + miso[3]
                return { "dataout": "GetIrqStatus()=" + hex(irqStatus) }

            # 0x17 = GetRxBufferStatus()
            if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x17:
                rxPayloadLen = miso[2]
                rxStartBufP = miso[3]
                return { "dataout": "GetRxBufferStatus()=rxPayloadLen=" + str(rxPayloadLen) + ", rxStartBuffP=" + hex(rxStartBufP) }

            # 0x18 = WriteRegister(address, data[0:n])
            if len(mosi) >= 4 and mosi[0] == 0x18:
                address = (mosi[1]<<8)+mosi[2]
                dataWR = hex(mosi[3])
                if len(mosi) > 4:
                    for x in range(4, len(mosi)):
                        dataWR += " " + hex(mosi[x])
                return { "dataout": "WriteRegister(@" + hex(address) + "," + dataWR + ")" }

            # 0x19 = ReadRegister(address)
            if len(mosi) >= 5 and len(miso) >= 5 and mosi[0] == 0x19:
                address = (mosi[1]<<8)+mosi[2]
                dataRR = hex(miso[4])
                if len(miso) > 5:
                    for x in range(5, len(miso)):
                        dataRR += " " + hex(miso[x])
                return { "dataout": "ReadRegister(@" + hex(address) + ")=" + dataRR }

            # 0x1A = WriteBuffer(offset, data[0:n])
            if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x1A:
                offset = mosi[1]
                dataWB = hex(mosi[2])
                if len(mosi) > 3:
                    for x in range(3, len(mosi)):
                        dataWB += " " + hex(mosi[x])
                return { "dataout": "WriteBuffer(offset=" + hex(offset) + ",data=" + dataWB + ")" }

            # 0x1B = ReadBuffer(offset)
            if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x1B:
                offset = mosi[1]
                length = str(len(miso) - 3)
                if length == 1:
                    return { "dataout": "ReadBuffer(offset=" + hex(offset) + ", 1 byte)" }
                else:
                    return { "dataout": "ReadBuffer(offset=" + hex(offset) + ", " + length + " bytes)" }

            # 0x1D = GetPacketStatus()
            if len(mosi) >= 7 and len(miso) >= 7 and mosi[0] == 0x1D:
                if self.packetType == PacketType.BLE or self.packetType == PacketType.GFSK or self.packetType == PacketType.FLRC:
                    if self.packetType == PacketType.BLE:
                        result = "BLE:"
                    if self.packetType == PacketType.GFSK:
                        result = "GFSK:"
                    if self.packetType == PacketType.FLRC:
                        result = "FLRC:"
                    result += "RFU=" + hex(miso[2])
                    result += ", rssiSync=" + str(-miso[3]/2) + " dBm"
                    result += ", errors=" + hex(miso[4])
                    result += ", status=" + hex(miso[5])
                    syncResult = "sync=ERROR"
                    if (miso[6] & 0x03) == 0: syncResult = ", SyncAddrDetection Error"
                    if (miso[6] & 0x03) == 1: syncResult = ", SyncAddr 1 detected"
                    if (miso[6] & 0x03) == 2: syncResult = ", SyncAddr 2 detected"
                    if (miso[6] & 0x03) == 3: syncResult = ", SyncAddr 3 detected"
                    result += ", " + syncResult
                    return { "dataout": "GetPacketStatus()=" + result}
                if self.packetType == PacketType.LORA or self.packetType == PacketType.RANGING:
                    if self.packetType == PacketType.LORA:
                        result = "LORA:"
                    if self.packetType == PacketType.RANGING:
                        result = "RANGING:"
                    result += "rssiSync=" + str(-miso[2]/2) + " dBm"
                    result += ", snr=" + str(miso[3]/4) + " dB"
                    return { "dataout": "GetPacketStatus()=" + result }
                return { "dataout": "GetPacketStatus()=UNDEFINED protocol" }

            # 0x1F = GetRssiInst()
            if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x1F:
                return { "dataout": "GetRssiInst()=" + str(-miso[2]/2) + " dBm" }
        
            # 0x80 = SetStandby(standbyConfig)
            if len(mosi) >= 2 and mosi[0] == 0x80:
                if mosi[1] == 0x00: return { "dataout": "SetStandby(RC)" }
                if mosi[1] == 0x01: return { "dataout": "SetStandby(XOSC)" }
                return { "dataout": "SetStandby(ERROR)" }

            # 0x82 = SetRx(periodBase, periodBaseCount)
            if len(mosi) >= 4 and mosi[0] == 0x82:
                periodBase = mosi[1]
                periodBaseCount = mosi[2]*256 + mosi[3]
                return { "dataout": "SetRx(periodBase=" + str(periodBase) + ",periodBaseCount=" + str(periodBaseCount) + ")" }

            # 0x83 = SetTx(periodBase, periodBaseCount)
            if len(mosi) >= 4 and mosi[0] == 0x83:
                periodBase = mosi[1]
                periodBaseCount = mosi[2]*256 + mosi[3]
                return { "dataout": "SetTx(periodBase=" + str(periodBase) + ",periodBaseCount=" + str(periodBaseCount) + ")" }
                
            #0x84 = SetSleep(sleepConfig)
            if len(mosi) >= 2 and mosi[0] == 0x84:
                if mosi[1] & 0x01: 
                    DR = "Data RAM flushed"
                else:
                    DR = "Data RAM retention"
                if mosi[1] & 0x02: 
                    DB = "Data buffer flushed"
                else:
                    DB = "Data buffer retention"
                return { "dataout": "SetSleep(" + DB + ", " + DR + ")" }
                
            # 0x86 = SetRfFrequency(rfFrequency)
            if len(mosi) >= 4 and mosi[0] == 0x86:
                rfFrequencyGHz = (mosi[1]*256*256 + mosi[2]*256 + mosi[3]) * 52/(1000*(2**18))
                return { "dataout": "SetRfFrequency(" + str(round(rfFrequencyGHz,9)) + " GHz)" }
                
            # 0x88 = SetCadParams(cadSymbolNum)
            if len(mosi) >= 2 and mosi[0] == 0x88:
                symbols = None
                if mosi[1] == 0x00: symbols = 1
                if mosi[1] == 0x20: symbols = 2
                if mosi[1] == 0x40: symbols = 4
                if mosi[1] == 0x60: symbols = 8
                if mosi[1] == 0x80: symbols = 16
                return { "dataout": "SetCadParams(symbols=" + str(symbols) + ")" }

            # 0x8A = SetPacketType(packetType)
            if len(mosi) >= 2 and mosi[0] == 0x8A:
                if mosi[1] == 0x00:
                    self.packetType = PacketType.GFSK
                    return { "dataout": "SetPacketType(GFSK)" }
                if mosi[1] == 0x01:
                    self.packetType = PacketType.LORA
                    return { "dataout": "SetPacketType(LORA)" }
                if mosi[1] == 0x02:
                    self.packetType = PacketType.RANGING
                    return { "dataout": "SetPacketType(RANGING)" }
                if mosi[1] == 0x03:
                    self.packetType = PacketType.FLRC
                    return { "dataout": "SetPacketType(FLRC)" }
                if mosi[1] == 0x04:
                    self.packetType = PacketType.BLE
                    return { "dataout": "SetPacketType(BLE)" }
                self.packetType = PacketType.UNDEFINED
                return { "dataout": "SetPacketType(Reserved)" }

            # 0x8B = SetModulationParams(modParam1, modParam2, modParam3)
            if len(mosi) >= 4 and mosi[0] == 0x8B:
                mP1 = mosi[1]
                mP2 = mosi[2]
                mP3 = mosi[3]
                result = ""
                if self.packetType == PacketType.LORA or self.packetType == PacketType.RANGING:
                    if self.packetType == PacketType.LORA:
                        result += "LORA:"
                    if self.packetType == PacketType.RANGING:
                        result += "RANGING:"
                    SP = None
                    if mP1 == 0x50: SP="5"
                    if mP1 == 0x60: SP="6"
                    if mP1 == 0x70: SP="7"
                    if mP1 == 0x80: SP="8"
                    if mP1 == 0x90: SP="9"
                    if mP1 == 0xA0: SP="10"
                    if self.packetType == PacketType.LORA:
                        # Not available for RANGING
                        if mP1 == 0xB0: SP="11"
                        if mP1 == 0xC0: SP="12"
                    if SP != None:
                        result += "SP=" + SP
                    else:
                        result += "SP=ERROR"
                    BW = None
                    if mP2 == 0x0A: BW="1625.0"
                    if mP2 == 0x18: BW="812.5"
                    if mP2 == 0x26: BW="406.25"
                    if self.packetType == PacketType.LORA:
                        if mP2 == 0x34: BW="203.125" # Not available for RANGING
                    if BW != None:
                        result += ",BW=" + BW + " kHz"
                    else:
                        result += ",BW=ERROR"
                    CR = None
                    if mP3 == 0x01: CR="4/5"
                    if mP3 == 0x02: CR="4/6"
                    if mP3 == 0x03: CR="4/7"
                    if mP3 == 0x04: CR="4/8"
                    if mP3 == 0x05: CR="4/5*"
                    if mP3 == 0x06: CR="4/6*"
                    if mP3 == 0x07: CR="4/8*"
                    if CR != None:
                        result += ",CR=" + CR
                    else:
                        result += ",CR=ERROR"
                if self.packetType == PacketType.GFSK or self.packetType == PacketType.BLE:
                    if self.packetType == PacketType.GFSK:
                        result += "GFSK:"
                    if self.packetType == PacketType.BLE:
                        result += "BLE:"
                    BR = None
                    BW = None
                    if mP1 == 0x04:
                        BR="2"
                        BW="2.4"
                    if mP1 == 0x28:
                        BR="1.6"
                        BW="2.4"
                    if mP1 == 0x4C:
                        BR="1"
                        BW="2.4"
                    if mP1 == 0x45:
                        BR="1"
                        BW="1.2"
                    if mP1 == 0x70:
                        BR="0.8"
                        BW="2.4"
                    if mP1 == 0x69:
                        BR="0.8"
                        BW="1.2"
                    if mP1 == 0x8D:
                        BR="0.5"
                        BW="1.2"
                    if mP1 == 0x86:
                        BR="0.5"
                        BW="0.6"
                    if mP1 == 0xB1:
                        BR="0.4"
                        BW="1.2"
                    if mP1 == 0xAA:
                        BR="0.4"
                        BW="0.6"
                    if mP1 == 0xCE:
                        BR="0.25"
                        BW="0.6"
                    if mP1 == 0xC7:
                        BR="0.25"
                        BW="0.3"
                    if mP1 == 0xEF:
                        BR="0.125"
                        BW="0.3"
                    if BR != None:
                        result += "BR=" + BR
                    else:
                        result += "BR=ERROR"
                    if BW != None:
                        result += ",BW=" + BW
                    else:
                        result += ",BW=ERROR"
                    
                    MI = None
                    if mP2 == 0x00: MI="0.35"
                    if mP2 == 0x01: MI="0.5"
                    if mP2 == 0x02: MI="0.75"
                    if mP2 == 0x03: MI="1"
                    if mP2 == 0x04: MI="1.25"
                    if mP2 == 0x05: MI="1.5"
                    if mP2 == 0x06: MI="1.75"
                    if mP2 == 0x07: MI="2"
                    if mP2 == 0x08: MI="2.25"
                    if mP2 == 0x09: MI="2.5"
                    if mP2 == 0x0A: MI="2.75"
                    if mP2 == 0x0B: MI="3"
                    if mP2 == 0x0C: MI="3.25"
                    if mP2 == 0x0D: MI="3.5"
                    if mP2 == 0x0E: MI="3.75"
                    if mP2 == 0x0F: MI="4"
                    if MI != None:
                        result += "MI=" + MI
                    else:
                        result += "MI=ERROR"
                    
                    BT = None
                    if mP3 == 0x00: BT="No filtering"
                    if mP3 == 0x10: BT="1"
                    if mP3 == 0x20: BT="0.5"
                    if BT != None:
                        result += "BT=" + BT
                    else:
                        result += "BT=ERROR"

                if self.packetType == PacketType.FLRC:
                    result += "FLRC:"
                    BR = None
                    BW = None
                    if mP1 == 0x45:
                        BR="1.3"
                        BW="1.2"
                    if mP1 == 0x69:
                        BR="1.04"
                        BW="1.2"
                    if mP1 == 0x86:
                        BR="0.65"
                        BW="0.6"
                    if mP1 == 0xAA:
                        BR="0.52"
                        BW="0.6"
                    if mP1 == 0xC7:
                        BR="0.325"
                        BW="0.3"
                    if mP1 == 0xEB:
                        BR="0.26"
                        BW="0.3"
                    if BR != None:
                        result += "BR=" + BR
                    else:
                        result += "BR=ERROR"
                    if BW != None:
                        result += ",BW=" + BW
                    else:
                        result += ",BW=ERROR"
                    CR = None
                    if mP2 == 0x00: CR="1/2"
                    if mP2 == 0x02: CR="3/4"
                    if mP2 == 0x04: CR="1"
                    if mP2 == 0x03 or mP2 >= 0x05: CR="Reserved"
                    if CR != None:
                        result += "CR=" + CR
                    else:
                        result += "CR=ERROR"
                    BT = None
                    if mP3 == 0x00: BT="No filtering"
                    if mP3 == 0x10: BT="1"
                    if mP3 == 0x20: BT="0.5"
                    if BT != None:
                        result += "BT=" + BT
                    else:
                        result += "BT=ERROR"

                if result == "": result = hex(mP1) + "," + hex(mP2) + "," + hex(mP3)
                return { "dataout": "SetModulationParams(" + result + ")" }
                
            # 0x8C = SetPacketParams(packetParam1 .. packetParam7)
            if len(mosi) >= 8 and mosi[0] == 0x8C:
                packetParam1 = mosi[1]
                packetParam2 = mosi[2]
                packetParam3 = mosi[3]
                packetParam4 = mosi[4]
                packetParam5 = mosi[5]
                packetParam6 = mosi[6]
                packetParam7 = mosi[7]
                result = ""
                
                if self.packetType == PacketType.GFSK or self.packetType == PacketType.FLRC:
                    if self.packetType == PacketType.GFSK:
                        result += "GFSK:"
                    if self.packetType == PacketType.FLRC:
                        result += "FLRC:"
                    result += "PreLen=" + str(packetParam1)
                    result += ",SWLen=" + str(packetParam2)
                    result += ",SWM=" + hex(packetParam3)
                    result += ",HT=" + hex(packetParam4)
                    result += ",PayLen=" + str(packetParam5)
                    result += ",CLen=" + str(packetParam6)
                    result += ",WH=" + hex(packetParam7)
                    
                if self.packetType == PacketType.BLE:
                    result += "BLE:"
                    result += "CS=" + hex(packetParam1)
                    result += ",CLen=" + str(packetParam2)
                    result += ",BTP=" + hex(packetParam3)
                    result += ",WH=" + hex(packetParam4)

                if self.packetType == PacketType.LORA or self.packetType == PacketType.RANGING:
                    if self.packetType == PacketType.LORA:
                        result += "LORA:"
                    if self.packetType == PacketType.RANGING:
                        result += "RANGING:"
                    result += "PreLen=" + str(packetParam1)
                    result += ",HT=" + hex(packetParam2)
                    result += ",PayLen=" + str(packetParam3)
                    result += ",CRC=" + hex(packetParam4)
                    result += ",Invert=" + hex(packetParam5)

                if result == "":
                    result = hex(packetParam1) + " " + hex(packetParam2) + " " + hex(packetParam3) + " " + hex(packetParam4) + " " + hex(packetParam5) + " " + hex(packetParam6) + " " + hex(packetParam7)
                return { "dataout": "SetPacketParams(" + result + ")" }
                
            # 0x8D = SetDioIrqParams(irqMask, dio1Mask .. dio3Mask)
            if len(mosi) >= 9 and mosi[0] == 0x8D:
                irqMask = mosi[1]*256 + mosi[2]
                dio1Mask = mosi[3]*256 + mosi[4]
                dio2Mask = mosi[5]*256 + mosi[6]
                dio3Mask = mosi[7]*256 + mosi[8]
                return { "dataout": "SetDioIrqParams(irqM=" + hex(irqMask) + ",dio1M=" + hex(dio1Mask) + ",dio2M=" + hex(dio2Mask) + ",dio3M=" + hex(dio3Mask)  + ")" }

            # 0x8E = SetTxParams(power, rampTime)
            if len(mosi) >= 3 and mosi[0] == 0x8E:
                power_dB = mosi[1] - 18
                if mosi[2] == 0x00: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=2us)" }
                if mosi[2] == 0x20: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=4us)" }
                if mosi[2] == 0x40: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=6us)" }
                if mosi[2] == 0x60: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=8us)" }
                if mosi[2] == 0x80: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=10us)" }
                if mosi[2] == 0xA0: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=12us)" }
                if mosi[2] == 0xC0: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=16us)" }
                if mosi[2] == 0xE0: return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=20us)" }
                return { "dataout": "SetTxParams(pwr=" + str(power_dB) + "dB, rampTime=ERROR)" }

            # 0x8F = SetBufferBaseAddress(txBaseAddress, rxBaseAddress)
            if len(mosi) >= 2 and mosi[0] == 0x8F:
                return { "dataout": "SetBufferBaseAddress(txBA=" + hex(mosi[1]) + ", rxBA=" + hex(mosi[2]) + ")" }

            # 0x94 = SetRxDutyCycle(rxPeriodBase,rxPeriodBaseCount,sleepPeriodBase,sleepPeriodBaseCount)
            if len(mosi) >= 7 and mosi[0] == 0x94:
                periodBase = mosi[1]
                rxPeriodBaseCount = mosi[2]*256 + mosi[3]
                sleepPeriodBase = mosi[4]
                sleepPeriodBaseCount = mosi[5]*256 + mosi[6]
                return { "dataout": "SetRxDutyCycle(pBase=" + str(periodBase) + ", rxPBCount=" + str(rxPeriodBaseCount) + ", sleepPer=" + str(sleepPeriodBase) + ", sleepPBCount" + str(sleepPeriodBaseCount) }
            
            # 0x96 = SetRegulatorMode(regulatorMode)
            if len(mosi) >= 2 and mosi[0] == 0x96:
                if mosi[1] == 0x00: return { "dataout": "SetRegulatorMode(LDO)" }
                if mosi[1] == 0x01: return { "dataout": "SetRegulatorMode(DC-DC)" }
                return { "dataout": "SetRegulatorMode(ERROR)" }
                
            # 0x97 = ClrIrqStatus(irqMask)
            if len(mosi) >= 3 and mosi[0] == 0x97:
                irqMask = mosi[1]*256 + mosi[2]
                if irqMask == 0xFFFF: return { "dataout": "ClrIrqStatus(ALL)" }
                return { "dataout": "ClrIrqStatus(" + hex(irqMask) + ")" }
            
            # 0x98 = SetAutoTx(time)
            if len(mosi) >= 3 and mosi[0] == 0x98:
                time = mosi[1]*256 + mosi[2]
                return { "dataout": "SetAutoTx(" + str(time) + " us)" }

            # 0x9A = SetAdvancedRanging(enable)
            if len(mosi) >= 2 and mosi[0] == 0x9A:
                result = "ERROR"
                if mosi[1] == 0x00: result = "disable"
                if mosi[1] == 0x01: result = "enable"
                return { "dataout": "SetAdvancedRanging(" + result + ")" }

            # 0x9B = SetLongPreamble(enable)
            if len(mosi) >= 2 and mosi[0] == 0x9B:
                result = "ERROR"
                if mosi[1] == 0: result = "disable"
                if mosi[1] == 1: result = "enable"
                return { "dataout": "SetLongPreamble(" + result + ")" }

            # 0x9D = SetUartSpeed(uartSpeed) UART only, not available with SPI

            # 0x9E = SetAutoFS(enable)
            if len(mosi) >= 2 and mosi[0] == 0x9E:
                if mosi[1] == 0x00: return { "dataout": "SetAutoFS(disable)" }
                if mosi[1] == 0x01: return { "dataout": "SetAutoFS(enable)" }
                return { "dataout": "SetAutoFS(ERROR)" }

            # 0xA3 = SetRangingRole(role)
            if len(mosi) >= 2 and mosi[0] == 0xA3:
                result = "ERROR"
                if mosi[1] == 0x00: result = "Slave"
                if mosi[1] == 0x01: result = "Master"
                return { "dataout": "SetRangingRole(" + result + ")" }
                
            # 0xC0 = GetStatus()
            if len(mosi) >= 1 and mosi[0] == 0xC0:
                return { "dataout": "GetStatus()" }
            
            # 0xC1 = SetFs()
            if len(mosi) >= 1 and mosi[0] == 0xC1:
                return { "dataout": "SetFs()" }
                
            # 0xC5 = SetCad()
            if len(mosi) >= 1 and mosi[0] == 0xC5:
                return { "dataout": "SetCad()" }

            # 0xD1 = SetTxContinuousWave()
            if len(mosi) >= 1 and mosi[0] == 0xD1:
                return { "dataout": "SetTxContinuousWave()" }

            # 0xD2 = SetTxContinuousPreamble()
            if len(mosi) >= 1 and mosi[0] == 0xD2:
                return { "dataout": "SetTxContinuousPreamble()" }
                
            # 0xD5 = SetSaveContext()
            if len(mosi) >= 1 and mosi[0] == 0xD5:
                return { "dataout": "SetSaveContext()" }

        print("Unknown(" + mosi.hex(' ') + ")");
        return { "dataout": "Unknown(" + mosi.hex(' ') + ")" }

    def handle_disable(self, frame):
        if self.is_valid_transaction():
            result = AnalyzerFrame(
                "SpiTransaction",
                self.transaction_start_time,
                frame.end_time,
                self.get_frame_data(),
            )
        else:
            result = AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Invalid SPI transaction (spi_enable={}, error={}, transaction_start_time={})".format(
                        self.spi_enable,
                        self.error,
                        self.transaction_start_time,
                    )
                }
            )

        self.reset()
        return result

    def handle_error(self, frame):
        result = AnalyzerFrame(
            "SpiTransactionError",
            frame.start_time,
            frame.end_time,
            {
                "error_info": "The clock was in the wrong state when the enable signal transitioned to active"
            }
        )
        self.reset()

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "enable":
            return self.handle_enable(frame)
        elif frame.type == "result":
            return self.handle_result(frame)
        elif frame.type == "disable":
            return self.handle_disable(frame)
        elif frame.type == "error":
            return self.handle_error(frame)
        else:
            return AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Unexpected frame type from input analyzer: {}".format(frame.type)
                }
            )
