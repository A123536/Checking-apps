#ifndef COMMON_H
#define COMMON_H
#include <QWidget>

#define SSH_ENABLE
class common
{

public:



    uint16_t ShortFromChar(const uint8_t *pInput);

    uint32_t LongFromChar(const uint8_t *pInput);

    void ShortToChar ( uint16_t Input, uint8_t *pOutput);

    void LongToChar(uint32_t Input, uint8_t *pOutput);

    uint16_t ShortFromCharLE(const uint8_t *pInput);

    uint32_t LongFromCharLE(const uint8_t *pInput);

    void ShortToCharLE ( uint16_t Input, uint8_t *pOutput);

    void LongToCharLE(uint32_t Input, uint8_t *pOutput);

    uint32_t Crc32(const uint8_t *pData,uint32_t DataLen);
};




#endif // COMMON_H
