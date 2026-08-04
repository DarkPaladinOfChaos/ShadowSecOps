#!/usr/bin/env python3
"""
PLC simulado - Servidor Modbus TCP
Práctica OT: Reconocimiento, Análisis de Seguridad y Forense en un Entorno OT Simulado (Modbus/SCADA)

Compatible con pymodbus 3.14.x (API device_id / ModbusDeviceContext)
"""

import logging
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext,
)
from pymodbus import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def build_context():
    # Simulamos registros típicos de un PLC:
    # - Coils: estados on/off (ej. bombas, válvulas)
    # - Discrete Inputs: sensores digitales (ej. sensores de nivel)
    # - Holding Registers: setpoints / valores de control (ej. temperatura, presión)
    # - Input Registers: lecturas de sensores analógicos (ej. flujo, RPM)

    coils = ModbusSequentialDataBlock(1, [1, 0, 1, 0, 1] + [0] * 95)           # 100 coils
    discrete_inputs = ModbusSequentialDataBlock(1, [1, 1, 0, 0, 1] + [0] * 95)  # 100 discrete inputs
    holding_registers = ModbusSequentialDataBlock(1, [350, 120, 75, 1000, 0] + [0] * 95)  # temp=350, presión=120...
    input_registers = ModbusSequentialDataBlock(1, [512, 275, 98, 44, 0] + [0] * 95)      # flujo=512, RPM=275...

    device = ModbusDeviceContext(
        di=discrete_inputs,
        co=coils,
        hr=holding_registers,
        ir=input_registers,
    )

    # Un único device con id 1 (puedes añadir más entradas al dict para simular varios PLCs)
    context = ModbusServerContext(devices={1: device}, single=False)
    return context


def build_identity():
    identity = ModbusDeviceIdentification()
    identity.VendorName = "ShadowSecOps Labs"
    identity.ProductCode = "PLC-SIM-01"
    identity.VendorUrl = "https://github.com/DarkPaladinOfChaos/ShadowSecOps"
    identity.ProductName = "Simulated Modbus PLC"
    identity.ModelName = "OT-Lab Controller"
    identity.MajorMinorRevision = "1.0"
    return identity


def main():
    context = build_context()
    identity = build_identity()

    log.info("Iniciando PLC simulado (Modbus TCP) en 0.0.0.0:502 ...")
    StartTcpServer(
        context=context,
        identity=identity,
        address=("0.0.0.0", 502),
    )


if __name__ == "__main__":
    main()
