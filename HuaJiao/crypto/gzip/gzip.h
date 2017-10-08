#pragma once

#ifndef gzip_h__
#define gzip_h__

#include <vector>

namespace gzip
{
	bool ungzip(std::vector<unsigned char>& in, size_t count_in, std::vector<unsigned char>& out, size_t& count_out);


	bool ungzip(std::vector<unsigned char>& in, std::vector<unsigned char>& out);
};

#endif // gzip_h__

