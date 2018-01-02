#ifndef MANAGER_COMMON_BLOCKWRITER_H
#define MANAGER_COMMON_BLOCKWRITER_H

#include <QBuffer>
#include <QDataStream>
#include <QIODevice>

class BlockWriter
{
    BlockWriter(const BlockWriter&) NO_METHOD; // no copy-ctor
    BlockWriter operator=(const BlockWriter&) NO_METHOD; // no copy-assign

public:
    BlockWriter(QIODevice *pdev) : dev(pdev), buffer(), stream()
    {
        buffer.open(QIODevice::WriteOnly);
        stream.setDevice(&buffer);
        stream << quint32(0); // placeholder; we will fill in real size later
    }

    ~BlockWriter()
    {
        // Fill in the real size.
        buffer.seek(0);
        stream << (quint32)buffer.size();

        // Write the buffer to the device.
        dev->write(buffer.buffer());
    }

    template <class T> BlockWriter &operator<<(const T &data)
	{ stream << data; return *this; }

private:
    QIODevice *dev;
    QBuffer buffer;
    QDataStream stream;
};

#endif // MANAGER_COMMON_BLOCKWRITER_H
