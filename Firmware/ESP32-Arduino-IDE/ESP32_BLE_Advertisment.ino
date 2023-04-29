#include <BLEDevice.h>

uint8_t adv_data[31] = {
  0x1e, /* Length (30) */
  0xff, /* Manufacturer Specific Data (type 0xff) */
  0x4c, 0x00, /* Company ID (Apple) */
  0x12, 0x19, /* Offline Finding type and length */
  0x00, /* State */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, /* First two bits */
  0x00, /* Hint (0x00) */
};

uint8_t advertisementKey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x1d, 0x2e, 0x3f};

void set_addr_from_key(esp_bd_addr_t addr, uint8_t *public_key) {
  addr[0] = public_key[0] | 0b11000000;
  addr[1] = public_key[1];
  addr[2] = public_key[2];
  addr[3] = public_key[3];
  addr[4] = public_key[4];
  addr[5] = public_key[5];
}

void set_payload_from_key(uint8_t *payload, uint8_t *public_key) {
  memcpy(&payload[7], &public_key[6], 22);
  payload[29] = public_key[0] >> 6;
}

void setup() {
  BLEDevice::init("");
  BLEServer *pServer = BLEDevice::createServer();

  esp_bd_addr_t addr;
  set_addr_from_key(addr, advertisementKey);
  set_payload_from_key(adv_data, advertisementKey);

  BLEAddress tagAddress = BLEAddress(addr);
  BLEAdvertisementData advData;
  advData.addData(std::string((char *)adv_data, sizeof(adv_data)));

  BLEAdvertising *advertising = pServer->getAdvertising();
  advertising->setAdvertisementData(advData);
  advertising->setDeviceAddress((uint8_t*)tagAddress.getNative(), BLE_ADDR_TYPE_RANDOM);
  advertising->setAdvertisementType(ADV_TYPE_NONCONN_IND);
  advertising->setMaxInterval(0x0C80);
  advertising->setMinInterval(0x0640);
  advertising->setAdvertisementChannelMap(ADV_CHNL_ALL);
  advertising->setScanFilter(false, false);
  advertising->start();
}

void loop() {
}


