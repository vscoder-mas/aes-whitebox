#ifndef WHITEBOX_UINT8_BUFFER_H_
#define WHITEBOX_UINT8_BUFFER_H_
#include <string>

namespace whitebox
{
    namespace utils
    {
        template <int PaddingSize>
        class WBUint8Buf
        {
        public:
            WBUint8Buf(const uint8_t *source, size_t source_size)
            {
                make_buff(source, source_size);
            }

            WBUint8Buf(const WBUint8Buf &) = delete;
            WBUint8Buf(WBUint8Buf && r)
            {
                buff_ = r.buff_;
                size_ = r.size_;
                r.buff_ = NULL;
                r.size_ = 0;
            }

            WBUint8Buf &operator=(const WBUint8Buf &) = delete;

            WBUint8Buf(std::string& source)
            {
                make_buff((const uint8_t*) source.data(), source.size());
            }

            std::string ToString()
            {
                return std::move(std::string((const char*)buff_));
            }

            WBUint8Buf(size_t fixed_size = 16)
            {
                size_ = fixed_size;
                buff_ = new uint8_t[size_];
                for (size_t i = 0; i < size_; i++)
                {
                    *(buff_ + i) = 0;
                }
            }

            uint8_t *BuffPtr()
            {
                return buff_;
            }

            size_t Size()
            {
                return size_;
            }

            ~WBUint8Buf()
            {
                if (buff_ != NULL)
                {
                    delete[] buff_;
                    buff_ = NULL;
                }
                size_ = 0;
            }

        private:
            void make_buff(const uint8_t *source, size_t source_size)
            {
                if (buff_ != NULL)
                {
                    delete[] buff_;
                }
                size_ = (source_size / PaddingSize + 1) * PaddingSize;
                buff_ = new uint8_t[size_];
                for (size_t i = 0; i < size_; i++)
                {
                    *(buff_ + i) = i < source_size ? *(source + i) : 0;
                }
            }

        private:
            uint8_t *buff_{NULL};
            size_t size_{0};
        };
        using WBUint8Buf_16 = WBUint8Buf<16>;
    }
}
#endif

