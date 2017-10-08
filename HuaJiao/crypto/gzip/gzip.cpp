
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <assert.h>

#include "gzip.h"
#include "zlib/zlib.h"

#ifdef _MSC_VER
#ifdef _DEBUG
#pragma comment(lib , "zlibstatic_d.lib")
#else
#pragma comment(lib , "zlibstatic.lib")
#endif // _DEBUG
#endif

namespace gzip
{
	bool ungzip(std::vector<unsigned char>& in, size_t count_in, std::vector<unsigned char>& out, size_t& count_out)
	{
		int ret, have;
		z_stream d_stream;
		char *compr, *uncompr;
		uLong comprLen, uncomprLen;
		compr = reinterpret_cast<char*>(&in[0]);
		comprLen = count_in;
		out.clear();
		out.resize(count_in * 16, 0);
		uncompr = reinterpret_cast<char*>(&out[0]);
		uncomprLen = out.size();
		memset(&d_stream, 0, sizeof(z_stream));
		d_stream.zalloc = Z_NULL;
		d_stream.zfree = Z_NULL;
		d_stream.opaque = Z_NULL;

		d_stream.next_in = Z_NULL;//inflateInit和inflateInit2都必须初始化next_in和avail_in
		d_stream.avail_in = 0;//deflateInit和deflateInit2则不用

		ret = inflateInit2(&d_stream, 47);
		if (ret != Z_OK)
		{
			printf("inflateInit2 error:%d", ret);
			return false;
		}
		count_out = 0;
		d_stream.next_in = reinterpret_cast<Byte*>(compr);
		d_stream.avail_in = comprLen;
		do
		{
			d_stream.next_out = reinterpret_cast<Byte*>(uncompr + count_out);
			d_stream.avail_out = uncomprLen - count_out;
			ret = inflate(&d_stream, Z_NO_FLUSH);
			_ASSERT(ret != Z_STREAM_ERROR);
			switch (ret)
			{
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)inflateEnd(&d_stream);
				return false;
			}
			have = uncomprLen - d_stream.avail_out;

			count_out += have;

		} while (d_stream.avail_out == 0);
		inflateEnd(&d_stream);

		if (count_out > out.size())
		{
			// crash it!!
			assert(false);
			throw std::system_error(std::error_code());
		};

		auto it = out.begin() + count_out;
		if (it != out.end())
			out.erase(it, out.end());

		return true;
	}

	bool ungzip(std::vector<unsigned char>& in, std::vector<unsigned char>& out)
	{
		int ret, have;
		z_stream d_stream;

		std::vector<unsigned char> v_temp;

		out.clear();
		out.reserve(in.size() * 10);
		v_temp.resize(4 * 1024, 0);

		memset(&d_stream, 0, sizeof(z_stream));
		d_stream.zalloc = Z_NULL;
		d_stream.zfree = Z_NULL;
		d_stream.opaque = Z_NULL;

		d_stream.next_in = Z_NULL;//inflateInit和inflateInit2都必须初始化next_in和avail_in
		d_stream.avail_in = 0;//deflateInit和deflateInit2则不用

		ret = inflateInit2(&d_stream, 47);
		if (ret != Z_OK)
		{
			printf("inflateInit2 error:%d", ret);
			return false;
		}
		d_stream.next_in = reinterpret_cast<Byte*>(&in[0]);
		d_stream.avail_in = in.size();

		do
		{
			d_stream.next_out = reinterpret_cast<Byte*>(&*v_temp.begin());
			d_stream.avail_out = v_temp.size();
			
			ret = inflate(&d_stream, Z_NO_FLUSH);
			
			_ASSERT(ret != Z_STREAM_ERROR);
			
			switch (ret)
			{
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)inflateEnd(&d_stream);
				return false;
			}
			
			have = v_temp.size() - d_stream.avail_out;
			
			if (have > 0)
				out.insert(out.end(), v_temp.begin(), v_temp.begin() + have);

		} while (d_stream.avail_out == 0);
		
		inflateEnd(&d_stream);

		return true;
	}
}