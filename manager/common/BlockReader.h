#ifndef MANAGER_COMMON_BLOCKREADER_H
#define MANAGER_COMMON_BLOCKREADER_H

#include <QBuffer>
#include <QDataStream>
#include <QIODevice>

// BlockReader provides a stream interface to read data written by a
// BlockWriter, blocking if needed to wait for transmission delays.  All the
// data written by a single BlockWriter must be read by a single BlockReader.
class BlockReader
{
public:
    BlockReader(QIODevice *dev) : buffer(), stream()
    {
        buffer.open(QIODevice::ReadWrite);
        stream.setDevice(&buffer);

	// Read size.
	quint32 size;
	readn(dev, sizeof(size));
	buffer.seek(0);
	stream >> size;

	// Read data from dev into buffer.
	readn(dev, size);
	buffer.seek(sizeof(size)); // beginning of data
    }

    template <class T> BlockReader &operator>>(T &data)
	{ stream >> data; return *this; }

private:
    // Read from dev into buffer until buffer contains exactly n bytes.
    void readn(QIODevice *dev, quint32 n)
    {
        while (buffer.size() < n && dev->isOpen()) {
            if (!dev->bytesAvailable())
                dev->waitForReadyRead(1000);
            buffer.write(dev->read(n - buffer.size()));
        }
    }

    QBuffer buffer;
    QDataStream stream;
};

#endif // MANAGER_COMMON_BLOCKREADER_H
