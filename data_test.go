package x509tools

var testExtensionValues = [][]byte{
	nil,
	{0x03, 0x02, 0x07, 0x80},
	{0x03, 0x02, 0x06, 0x40},
	{0x03, 0x02, 0x06, 0xC0},
	{0x03, 0x02, 0x05, 0x20},
	{0x03, 0x02, 0x05, 0xA0},
	{0x03, 0x02, 0x05, 0x60},
	{0x03, 0x02, 0x05, 0xE0},
	{0x03, 0x02, 0x04, 0x10},
	{0x03, 0x02, 0x04, 0x90},
	{0x03, 0x02, 0x04, 0x50},
	{0x03, 0x02, 0x04, 0xD0},
	{0x03, 0x02, 0x04, 0x30},
	{0x03, 0x02, 0x04, 0xB0},
	{0x03, 0x02, 0x04, 0x70},
	{0x03, 0x02, 0x04, 0xF0},
	{0x03, 0x02, 0x03, 0x08},
	{0x03, 0x02, 0x03, 0x88},
	{0x03, 0x02, 0x03, 0x48},
	{0x03, 0x02, 0x03, 0xC8},
	{0x03, 0x02, 0x03, 0x28},
	{0x03, 0x02, 0x03, 0xA8},
	{0x03, 0x02, 0x03, 0x68},
	{0x03, 0x02, 0x03, 0xE8},
	{0x03, 0x02, 0x03, 0x18},
	{0x03, 0x02, 0x03, 0x98},
	{0x03, 0x02, 0x03, 0x58},
	{0x03, 0x02, 0x03, 0xD8},
	{0x03, 0x02, 0x03, 0x38},
	{0x03, 0x02, 0x03, 0xB8},
	{0x03, 0x02, 0x03, 0x78},
	{0x03, 0x02, 0x03, 0xF8},
	{0x03, 0x02, 0x02, 0x04},
	{0x03, 0x02, 0x02, 0x84},
	{0x03, 0x02, 0x02, 0x44},
	{0x03, 0x02, 0x02, 0xC4},
	{0x03, 0x02, 0x02, 0x24},
	{0x03, 0x02, 0x02, 0xA4},
	{0x03, 0x02, 0x02, 0x64},
	{0x03, 0x02, 0x02, 0xE4},
	{0x03, 0x02, 0x02, 0x14},
	{0x03, 0x02, 0x02, 0x94},
	{0x03, 0x02, 0x02, 0x54},
	{0x03, 0x02, 0x02, 0xD4},
	{0x03, 0x02, 0x02, 0x34},
	{0x03, 0x02, 0x02, 0xB4},
	{0x03, 0x02, 0x02, 0x74},
	{0x03, 0x02, 0x02, 0xF4},
	{0x03, 0x02, 0x02, 0x0C},
	{0x03, 0x02, 0x02, 0x8C},
	{0x03, 0x02, 0x02, 0x4C},
	{0x03, 0x02, 0x02, 0xCC},
	{0x03, 0x02, 0x02, 0x2C},
	{0x03, 0x02, 0x02, 0xAC},
	{0x03, 0x02, 0x02, 0x6C},
	{0x03, 0x02, 0x02, 0xEC},
	{0x03, 0x02, 0x02, 0x1C},
	{0x03, 0x02, 0x02, 0x9C},
	{0x03, 0x02, 0x02, 0x5C},
	{0x03, 0x02, 0x02, 0xDC},
	{0x03, 0x02, 0x02, 0x3C},
	{0x03, 0x02, 0x02, 0xBC},
	{0x03, 0x02, 0x02, 0x7C},
	{0x03, 0x02, 0x02, 0xFC},
	{0x03, 0x02, 0x01, 0x02},
	{0x03, 0x02, 0x01, 0x82},
	{0x03, 0x02, 0x01, 0x42},
	{0x03, 0x02, 0x01, 0xC2},
	{0x03, 0x02, 0x01, 0x22},
	{0x03, 0x02, 0x01, 0xA2},
	{0x03, 0x02, 0x01, 0x62},
	{0x03, 0x02, 0x01, 0xE2},
	{0x03, 0x02, 0x01, 0x12},
	{0x03, 0x02, 0x01, 0x92},
	{0x03, 0x02, 0x01, 0x52},
	{0x03, 0x02, 0x01, 0xD2},
	{0x03, 0x02, 0x01, 0x32},
	{0x03, 0x02, 0x01, 0xB2},
	{0x03, 0x02, 0x01, 0x72},
	{0x03, 0x02, 0x01, 0xF2},
	{0x03, 0x02, 0x01, 0x0A},
	{0x03, 0x02, 0x01, 0x8A},
	{0x03, 0x02, 0x01, 0x4A},
	{0x03, 0x02, 0x01, 0xCA},
	{0x03, 0x02, 0x01, 0x2A},
	{0x03, 0x02, 0x01, 0xAA},
	{0x03, 0x02, 0x01, 0x6A},
	{0x03, 0x02, 0x01, 0xEA},
	{0x03, 0x02, 0x01, 0x1A},
	{0x03, 0x02, 0x01, 0x9A},
	{0x03, 0x02, 0x01, 0x5A},
	{0x03, 0x02, 0x01, 0xDA},
	{0x03, 0x02, 0x01, 0x3A},
	{0x03, 0x02, 0x01, 0xBA},
	{0x03, 0x02, 0x01, 0x7A},
	{0x03, 0x02, 0x01, 0xFA},
	{0x03, 0x02, 0x01, 0x06},
	{0x03, 0x02, 0x01, 0x86},
	{0x03, 0x02, 0x01, 0x46},
	{0x03, 0x02, 0x01, 0xC6},
	{0x03, 0x02, 0x01, 0x26},
	{0x03, 0x02, 0x01, 0xA6},
	{0x03, 0x02, 0x01, 0x66},
	{0x03, 0x02, 0x01, 0xE6},
	{0x03, 0x02, 0x01, 0x16},
	{0x03, 0x02, 0x01, 0x96},
	{0x03, 0x02, 0x01, 0x56},
	{0x03, 0x02, 0x01, 0xD6},
	{0x03, 0x02, 0x01, 0x36},
	{0x03, 0x02, 0x01, 0xB6},
	{0x03, 0x02, 0x01, 0x76},
	{0x03, 0x02, 0x01, 0xF6},
	{0x03, 0x02, 0x01, 0x0E},
	{0x03, 0x02, 0x01, 0x8E},
	{0x03, 0x02, 0x01, 0x4E},
	{0x03, 0x02, 0x01, 0xCE},
	{0x03, 0x02, 0x01, 0x2E},
	{0x03, 0x02, 0x01, 0xAE},
	{0x03, 0x02, 0x01, 0x6E},
	{0x03, 0x02, 0x01, 0xEE},
	{0x03, 0x02, 0x01, 0x1E},
	{0x03, 0x02, 0x01, 0x9E},
	{0x03, 0x02, 0x01, 0x5E},
	{0x03, 0x02, 0x01, 0xDE},
	{0x03, 0x02, 0x01, 0x3E},
	{0x03, 0x02, 0x01, 0xBE},
	{0x03, 0x02, 0x01, 0x7E},
	{0x03, 0x02, 0x01, 0xFE},
	{0x03, 0x02, 0x00, 0x01},
	{0x03, 0x02, 0x00, 0x81},
	{0x03, 0x02, 0x00, 0x41},
	{0x03, 0x02, 0x00, 0xC1},
	{0x03, 0x02, 0x00, 0x21},
	{0x03, 0x02, 0x00, 0xA1},
	{0x03, 0x02, 0x00, 0x61},
	{0x03, 0x02, 0x00, 0xE1},
	{0x03, 0x02, 0x00, 0x11},
	{0x03, 0x02, 0x00, 0x91},
	{0x03, 0x02, 0x00, 0x51},
	{0x03, 0x02, 0x00, 0xD1},
	{0x03, 0x02, 0x00, 0x31},
	{0x03, 0x02, 0x00, 0xB1},
	{0x03, 0x02, 0x00, 0x71},
	{0x03, 0x02, 0x00, 0xF1},
	{0x03, 0x02, 0x00, 0x09},
	{0x03, 0x02, 0x00, 0x89},
	{0x03, 0x02, 0x00, 0x49},
	{0x03, 0x02, 0x00, 0xC9},
	{0x03, 0x02, 0x00, 0x29},
	{0x03, 0x02, 0x00, 0xA9},
	{0x03, 0x02, 0x00, 0x69},
	{0x03, 0x02, 0x00, 0xE9},
	{0x03, 0x02, 0x00, 0x19},
	{0x03, 0x02, 0x00, 0x99},
	{0x03, 0x02, 0x00, 0x59},
	{0x03, 0x02, 0x00, 0xD9},
	{0x03, 0x02, 0x00, 0x39},
	{0x03, 0x02, 0x00, 0xB9},
	{0x03, 0x02, 0x00, 0x79},
	{0x03, 0x02, 0x00, 0xF9},
	{0x03, 0x02, 0x00, 0x05},
	{0x03, 0x02, 0x00, 0x85},
	{0x03, 0x02, 0x00, 0x45},
	{0x03, 0x02, 0x00, 0xC5},
	{0x03, 0x02, 0x00, 0x25},
	{0x03, 0x02, 0x00, 0xA5},
	{0x03, 0x02, 0x00, 0x65},
	{0x03, 0x02, 0x00, 0xE5},
	{0x03, 0x02, 0x00, 0x15},
	{0x03, 0x02, 0x00, 0x95},
	{0x03, 0x02, 0x00, 0x55},
	{0x03, 0x02, 0x00, 0xD5},
	{0x03, 0x02, 0x00, 0x35},
	{0x03, 0x02, 0x00, 0xB5},
	{0x03, 0x02, 0x00, 0x75},
	{0x03, 0x02, 0x00, 0xF5},
	{0x03, 0x02, 0x00, 0x0D},
	{0x03, 0x02, 0x00, 0x8D},
	{0x03, 0x02, 0x00, 0x4D},
	{0x03, 0x02, 0x00, 0xCD},
	{0x03, 0x02, 0x00, 0x2D},
	{0x03, 0x02, 0x00, 0xAD},
	{0x03, 0x02, 0x00, 0x6D},
	{0x03, 0x02, 0x00, 0xED},
	{0x03, 0x02, 0x00, 0x1D},
	{0x03, 0x02, 0x00, 0x9D},
	{0x03, 0x02, 0x00, 0x5D},
	{0x03, 0x02, 0x00, 0xDD},
	{0x03, 0x02, 0x00, 0x3D},
	{0x03, 0x02, 0x00, 0xBD},
	{0x03, 0x02, 0x00, 0x7D},
	{0x03, 0x02, 0x00, 0xFD},
	{0x03, 0x02, 0x00, 0x03},
	{0x03, 0x02, 0x00, 0x83},
	{0x03, 0x02, 0x00, 0x43},
	{0x03, 0x02, 0x00, 0xC3},
	{0x03, 0x02, 0x00, 0x23},
	{0x03, 0x02, 0x00, 0xA3},
	{0x03, 0x02, 0x00, 0x63},
	{0x03, 0x02, 0x00, 0xE3},
	{0x03, 0x02, 0x00, 0x13},
	{0x03, 0x02, 0x00, 0x93},
	{0x03, 0x02, 0x00, 0x53},
	{0x03, 0x02, 0x00, 0xD3},
	{0x03, 0x02, 0x00, 0x33},
	{0x03, 0x02, 0x00, 0xB3},
	{0x03, 0x02, 0x00, 0x73},
	{0x03, 0x02, 0x00, 0xF3},
	{0x03, 0x02, 0x00, 0x0B},
	{0x03, 0x02, 0x00, 0x8B},
	{0x03, 0x02, 0x00, 0x4B},
	{0x03, 0x02, 0x00, 0xCB},
	{0x03, 0x02, 0x00, 0x2B},
	{0x03, 0x02, 0x00, 0xAB},
	{0x03, 0x02, 0x00, 0x6B},
	{0x03, 0x02, 0x00, 0xEB},
	{0x03, 0x02, 0x00, 0x1B},
	{0x03, 0x02, 0x00, 0x9B},
	{0x03, 0x02, 0x00, 0x5B},
	{0x03, 0x02, 0x00, 0xDB},
	{0x03, 0x02, 0x00, 0x3B},
	{0x03, 0x02, 0x00, 0xBB},
	{0x03, 0x02, 0x00, 0x7B},
	{0x03, 0x02, 0x00, 0xFB},
	{0x03, 0x02, 0x00, 0x07},
	{0x03, 0x02, 0x00, 0x87},
	{0x03, 0x02, 0x00, 0x47},
	{0x03, 0x02, 0x00, 0xC7},
	{0x03, 0x02, 0x00, 0x27},
	{0x03, 0x02, 0x00, 0xA7},
	{0x03, 0x02, 0x00, 0x67},
	{0x03, 0x02, 0x00, 0xE7},
	{0x03, 0x02, 0x00, 0x17},
	{0x03, 0x02, 0x00, 0x97},
	{0x03, 0x02, 0x00, 0x57},
	{0x03, 0x02, 0x00, 0xD7},
	{0x03, 0x02, 0x00, 0x37},
	{0x03, 0x02, 0x00, 0xB7},
	{0x03, 0x02, 0x00, 0x77},
	{0x03, 0x02, 0x00, 0xF7},
	{0x03, 0x02, 0x00, 0x0F},
	{0x03, 0x02, 0x00, 0x8F},
	{0x03, 0x02, 0x00, 0x4F},
	{0x03, 0x02, 0x00, 0xCF},
	{0x03, 0x02, 0x00, 0x2F},
	{0x03, 0x02, 0x00, 0xAF},
	{0x03, 0x02, 0x00, 0x6F},
	{0x03, 0x02, 0x00, 0xEF},
	{0x03, 0x02, 0x00, 0x1F},
	{0x03, 0x02, 0x00, 0x9F},
	{0x03, 0x02, 0x00, 0x5F},
	{0x03, 0x02, 0x00, 0xDF},
	{0x03, 0x02, 0x00, 0x3F},
	{0x03, 0x02, 0x00, 0xBF},
	{0x03, 0x02, 0x00, 0x7F},
	{0x03, 0x02, 0x00, 0xFF},
	{0x03, 0x03, 0x07, 0x00, 0x80},
	{0x03, 0x03, 0x07, 0x80, 0x80},
	{0x03, 0x03, 0x07, 0x40, 0x80},
	{0x03, 0x03, 0x07, 0xC0, 0x80},
	{0x03, 0x03, 0x07, 0x20, 0x80},
	{0x03, 0x03, 0x07, 0xA0, 0x80},
	{0x03, 0x03, 0x07, 0x60, 0x80},
	{0x03, 0x03, 0x07, 0xE0, 0x80},
	{0x03, 0x03, 0x07, 0x10, 0x80},
	{0x03, 0x03, 0x07, 0x90, 0x80},
	{0x03, 0x03, 0x07, 0x50, 0x80},
	{0x03, 0x03, 0x07, 0xD0, 0x80},
	{0x03, 0x03, 0x07, 0x30, 0x80},
	{0x03, 0x03, 0x07, 0xB0, 0x80},
	{0x03, 0x03, 0x07, 0x70, 0x80},
	{0x03, 0x03, 0x07, 0xF0, 0x80},
	{0x03, 0x03, 0x07, 0x08, 0x80},
	{0x03, 0x03, 0x07, 0x88, 0x80},
	{0x03, 0x03, 0x07, 0x48, 0x80},
	{0x03, 0x03, 0x07, 0xC8, 0x80},
	{0x03, 0x03, 0x07, 0x28, 0x80},
	{0x03, 0x03, 0x07, 0xA8, 0x80},
	{0x03, 0x03, 0x07, 0x68, 0x80},
	{0x03, 0x03, 0x07, 0xE8, 0x80},
	{0x03, 0x03, 0x07, 0x18, 0x80},
	{0x03, 0x03, 0x07, 0x98, 0x80},
	{0x03, 0x03, 0x07, 0x58, 0x80},
	{0x03, 0x03, 0x07, 0xD8, 0x80},
	{0x03, 0x03, 0x07, 0x38, 0x80},
	{0x03, 0x03, 0x07, 0xB8, 0x80},
	{0x03, 0x03, 0x07, 0x78, 0x80},
	{0x03, 0x03, 0x07, 0xF8, 0x80},
	{0x03, 0x03, 0x07, 0x04, 0x80},
	{0x03, 0x03, 0x07, 0x84, 0x80},
	{0x03, 0x03, 0x07, 0x44, 0x80},
	{0x03, 0x03, 0x07, 0xC4, 0x80},
	{0x03, 0x03, 0x07, 0x24, 0x80},
	{0x03, 0x03, 0x07, 0xA4, 0x80},
	{0x03, 0x03, 0x07, 0x64, 0x80},
	{0x03, 0x03, 0x07, 0xE4, 0x80},
	{0x03, 0x03, 0x07, 0x14, 0x80},
	{0x03, 0x03, 0x07, 0x94, 0x80},
	{0x03, 0x03, 0x07, 0x54, 0x80},
	{0x03, 0x03, 0x07, 0xD4, 0x80},
	{0x03, 0x03, 0x07, 0x34, 0x80},
	{0x03, 0x03, 0x07, 0xB4, 0x80},
	{0x03, 0x03, 0x07, 0x74, 0x80},
	{0x03, 0x03, 0x07, 0xF4, 0x80},
	{0x03, 0x03, 0x07, 0x0C, 0x80},
	{0x03, 0x03, 0x07, 0x8C, 0x80},
	{0x03, 0x03, 0x07, 0x4C, 0x80},
	{0x03, 0x03, 0x07, 0xCC, 0x80},
	{0x03, 0x03, 0x07, 0x2C, 0x80},
	{0x03, 0x03, 0x07, 0xAC, 0x80},
	{0x03, 0x03, 0x07, 0x6C, 0x80},
	{0x03, 0x03, 0x07, 0xEC, 0x80},
	{0x03, 0x03, 0x07, 0x1C, 0x80},
	{0x03, 0x03, 0x07, 0x9C, 0x80},
	{0x03, 0x03, 0x07, 0x5C, 0x80},
	{0x03, 0x03, 0x07, 0xDC, 0x80},
	{0x03, 0x03, 0x07, 0x3C, 0x80},
	{0x03, 0x03, 0x07, 0xBC, 0x80},
	{0x03, 0x03, 0x07, 0x7C, 0x80},
	{0x03, 0x03, 0x07, 0xFC, 0x80},
	{0x03, 0x03, 0x07, 0x02, 0x80},
	{0x03, 0x03, 0x07, 0x82, 0x80},
	{0x03, 0x03, 0x07, 0x42, 0x80},
	{0x03, 0x03, 0x07, 0xC2, 0x80},
	{0x03, 0x03, 0x07, 0x22, 0x80},
	{0x03, 0x03, 0x07, 0xA2, 0x80},
	{0x03, 0x03, 0x07, 0x62, 0x80},
	{0x03, 0x03, 0x07, 0xE2, 0x80},
	{0x03, 0x03, 0x07, 0x12, 0x80},
	{0x03, 0x03, 0x07, 0x92, 0x80},
	{0x03, 0x03, 0x07, 0x52, 0x80},
	{0x03, 0x03, 0x07, 0xD2, 0x80},
	{0x03, 0x03, 0x07, 0x32, 0x80},
	{0x03, 0x03, 0x07, 0xB2, 0x80},
	{0x03, 0x03, 0x07, 0x72, 0x80},
	{0x03, 0x03, 0x07, 0xF2, 0x80},
	{0x03, 0x03, 0x07, 0x0A, 0x80},
	{0x03, 0x03, 0x07, 0x8A, 0x80},
	{0x03, 0x03, 0x07, 0x4A, 0x80},
	{0x03, 0x03, 0x07, 0xCA, 0x80},
	{0x03, 0x03, 0x07, 0x2A, 0x80},
	{0x03, 0x03, 0x07, 0xAA, 0x80},
	{0x03, 0x03, 0x07, 0x6A, 0x80},
	{0x03, 0x03, 0x07, 0xEA, 0x80},
	{0x03, 0x03, 0x07, 0x1A, 0x80},
	{0x03, 0x03, 0x07, 0x9A, 0x80},
	{0x03, 0x03, 0x07, 0x5A, 0x80},
	{0x03, 0x03, 0x07, 0xDA, 0x80},
	{0x03, 0x03, 0x07, 0x3A, 0x80},
	{0x03, 0x03, 0x07, 0xBA, 0x80},
	{0x03, 0x03, 0x07, 0x7A, 0x80},
	{0x03, 0x03, 0x07, 0xFA, 0x80},
	{0x03, 0x03, 0x07, 0x06, 0x80},
	{0x03, 0x03, 0x07, 0x86, 0x80},
	{0x03, 0x03, 0x07, 0x46, 0x80},
	{0x03, 0x03, 0x07, 0xC6, 0x80},
	{0x03, 0x03, 0x07, 0x26, 0x80},
	{0x03, 0x03, 0x07, 0xA6, 0x80},
	{0x03, 0x03, 0x07, 0x66, 0x80},
	{0x03, 0x03, 0x07, 0xE6, 0x80},
	{0x03, 0x03, 0x07, 0x16, 0x80},
	{0x03, 0x03, 0x07, 0x96, 0x80},
	{0x03, 0x03, 0x07, 0x56, 0x80},
	{0x03, 0x03, 0x07, 0xD6, 0x80},
	{0x03, 0x03, 0x07, 0x36, 0x80},
	{0x03, 0x03, 0x07, 0xB6, 0x80},
	{0x03, 0x03, 0x07, 0x76, 0x80},
	{0x03, 0x03, 0x07, 0xF6, 0x80},
	{0x03, 0x03, 0x07, 0x0E, 0x80},
	{0x03, 0x03, 0x07, 0x8E, 0x80},
	{0x03, 0x03, 0x07, 0x4E, 0x80},
	{0x03, 0x03, 0x07, 0xCE, 0x80},
	{0x03, 0x03, 0x07, 0x2E, 0x80},
	{0x03, 0x03, 0x07, 0xAE, 0x80},
	{0x03, 0x03, 0x07, 0x6E, 0x80},
	{0x03, 0x03, 0x07, 0xEE, 0x80},
	{0x03, 0x03, 0x07, 0x1E, 0x80},
	{0x03, 0x03, 0x07, 0x9E, 0x80},
	{0x03, 0x03, 0x07, 0x5E, 0x80},
	{0x03, 0x03, 0x07, 0xDE, 0x80},
	{0x03, 0x03, 0x07, 0x3E, 0x80},
	{0x03, 0x03, 0x07, 0xBE, 0x80},
	{0x03, 0x03, 0x07, 0x7E, 0x80},
	{0x03, 0x03, 0x07, 0xFE, 0x80},
	{0x03, 0x03, 0x07, 0x01, 0x80},
	{0x03, 0x03, 0x07, 0x81, 0x80},
	{0x03, 0x03, 0x07, 0x41, 0x80},
	{0x03, 0x03, 0x07, 0xC1, 0x80},
	{0x03, 0x03, 0x07, 0x21, 0x80},
	{0x03, 0x03, 0x07, 0xA1, 0x80},
	{0x03, 0x03, 0x07, 0x61, 0x80},
	{0x03, 0x03, 0x07, 0xE1, 0x80},
	{0x03, 0x03, 0x07, 0x11, 0x80},
	{0x03, 0x03, 0x07, 0x91, 0x80},
	{0x03, 0x03, 0x07, 0x51, 0x80},
	{0x03, 0x03, 0x07, 0xD1, 0x80},
	{0x03, 0x03, 0x07, 0x31, 0x80},
	{0x03, 0x03, 0x07, 0xB1, 0x80},
	{0x03, 0x03, 0x07, 0x71, 0x80},
	{0x03, 0x03, 0x07, 0xF1, 0x80},
	{0x03, 0x03, 0x07, 0x09, 0x80},
	{0x03, 0x03, 0x07, 0x89, 0x80},
	{0x03, 0x03, 0x07, 0x49, 0x80},
	{0x03, 0x03, 0x07, 0xC9, 0x80},
	{0x03, 0x03, 0x07, 0x29, 0x80},
	{0x03, 0x03, 0x07, 0xA9, 0x80},
	{0x03, 0x03, 0x07, 0x69, 0x80},
	{0x03, 0x03, 0x07, 0xE9, 0x80},
	{0x03, 0x03, 0x07, 0x19, 0x80},
	{0x03, 0x03, 0x07, 0x99, 0x80},
	{0x03, 0x03, 0x07, 0x59, 0x80},
	{0x03, 0x03, 0x07, 0xD9, 0x80},
	{0x03, 0x03, 0x07, 0x39, 0x80},
	{0x03, 0x03, 0x07, 0xB9, 0x80},
	{0x03, 0x03, 0x07, 0x79, 0x80},
	{0x03, 0x03, 0x07, 0xF9, 0x80},
	{0x03, 0x03, 0x07, 0x05, 0x80},
	{0x03, 0x03, 0x07, 0x85, 0x80},
	{0x03, 0x03, 0x07, 0x45, 0x80},
	{0x03, 0x03, 0x07, 0xC5, 0x80},
	{0x03, 0x03, 0x07, 0x25, 0x80},
	{0x03, 0x03, 0x07, 0xA5, 0x80},
	{0x03, 0x03, 0x07, 0x65, 0x80},
	{0x03, 0x03, 0x07, 0xE5, 0x80},
	{0x03, 0x03, 0x07, 0x15, 0x80},
	{0x03, 0x03, 0x07, 0x95, 0x80},
	{0x03, 0x03, 0x07, 0x55, 0x80},
	{0x03, 0x03, 0x07, 0xD5, 0x80},
	{0x03, 0x03, 0x07, 0x35, 0x80},
	{0x03, 0x03, 0x07, 0xB5, 0x80},
	{0x03, 0x03, 0x07, 0x75, 0x80},
	{0x03, 0x03, 0x07, 0xF5, 0x80},
	{0x03, 0x03, 0x07, 0x0D, 0x80},
	{0x03, 0x03, 0x07, 0x8D, 0x80},
	{0x03, 0x03, 0x07, 0x4D, 0x80},
	{0x03, 0x03, 0x07, 0xCD, 0x80},
	{0x03, 0x03, 0x07, 0x2D, 0x80},
	{0x03, 0x03, 0x07, 0xAD, 0x80},
	{0x03, 0x03, 0x07, 0x6D, 0x80},
	{0x03, 0x03, 0x07, 0xED, 0x80},
	{0x03, 0x03, 0x07, 0x1D, 0x80},
	{0x03, 0x03, 0x07, 0x9D, 0x80},
	{0x03, 0x03, 0x07, 0x5D, 0x80},
	{0x03, 0x03, 0x07, 0xDD, 0x80},
	{0x03, 0x03, 0x07, 0x3D, 0x80},
	{0x03, 0x03, 0x07, 0xBD, 0x80},
	{0x03, 0x03, 0x07, 0x7D, 0x80},
	{0x03, 0x03, 0x07, 0xFD, 0x80},
	{0x03, 0x03, 0x07, 0x03, 0x80},
	{0x03, 0x03, 0x07, 0x83, 0x80},
	{0x03, 0x03, 0x07, 0x43, 0x80},
	{0x03, 0x03, 0x07, 0xC3, 0x80},
	{0x03, 0x03, 0x07, 0x23, 0x80},
	{0x03, 0x03, 0x07, 0xA3, 0x80},
	{0x03, 0x03, 0x07, 0x63, 0x80},
	{0x03, 0x03, 0x07, 0xE3, 0x80},
	{0x03, 0x03, 0x07, 0x13, 0x80},
	{0x03, 0x03, 0x07, 0x93, 0x80},
	{0x03, 0x03, 0x07, 0x53, 0x80},
	{0x03, 0x03, 0x07, 0xD3, 0x80},
	{0x03, 0x03, 0x07, 0x33, 0x80},
	{0x03, 0x03, 0x07, 0xB3, 0x80},
	{0x03, 0x03, 0x07, 0x73, 0x80},
	{0x03, 0x03, 0x07, 0xF3, 0x80},
	{0x03, 0x03, 0x07, 0x0B, 0x80},
	{0x03, 0x03, 0x07, 0x8B, 0x80},
	{0x03, 0x03, 0x07, 0x4B, 0x80},
	{0x03, 0x03, 0x07, 0xCB, 0x80},
	{0x03, 0x03, 0x07, 0x2B, 0x80},
	{0x03, 0x03, 0x07, 0xAB, 0x80},
	{0x03, 0x03, 0x07, 0x6B, 0x80},
	{0x03, 0x03, 0x07, 0xEB, 0x80},
	{0x03, 0x03, 0x07, 0x1B, 0x80},
	{0x03, 0x03, 0x07, 0x9B, 0x80},
	{0x03, 0x03, 0x07, 0x5B, 0x80},
	{0x03, 0x03, 0x07, 0xDB, 0x80},
	{0x03, 0x03, 0x07, 0x3B, 0x80},
	{0x03, 0x03, 0x07, 0xBB, 0x80},
	{0x03, 0x03, 0x07, 0x7B, 0x80},
	{0x03, 0x03, 0x07, 0xFB, 0x80},
	{0x03, 0x03, 0x07, 0x07, 0x80},
	{0x03, 0x03, 0x07, 0x87, 0x80},
	{0x03, 0x03, 0x07, 0x47, 0x80},
	{0x03, 0x03, 0x07, 0xC7, 0x80},
	{0x03, 0x03, 0x07, 0x27, 0x80},
	{0x03, 0x03, 0x07, 0xA7, 0x80},
	{0x03, 0x03, 0x07, 0x67, 0x80},
	{0x03, 0x03, 0x07, 0xE7, 0x80},
	{0x03, 0x03, 0x07, 0x17, 0x80},
	{0x03, 0x03, 0x07, 0x97, 0x80},
	{0x03, 0x03, 0x07, 0x57, 0x80},
	{0x03, 0x03, 0x07, 0xD7, 0x80},
	{0x03, 0x03, 0x07, 0x37, 0x80},
	{0x03, 0x03, 0x07, 0xB7, 0x80},
	{0x03, 0x03, 0x07, 0x77, 0x80},
	{0x03, 0x03, 0x07, 0xF7, 0x80},
	{0x03, 0x03, 0x07, 0x0F, 0x80},
	{0x03, 0x03, 0x07, 0x8F, 0x80},
	{0x03, 0x03, 0x07, 0x4F, 0x80},
	{0x03, 0x03, 0x07, 0xCF, 0x80},
	{0x03, 0x03, 0x07, 0x2F, 0x80},
	{0x03, 0x03, 0x07, 0xAF, 0x80},
	{0x03, 0x03, 0x07, 0x6F, 0x80},
	{0x03, 0x03, 0x07, 0xEF, 0x80},
	{0x03, 0x03, 0x07, 0x1F, 0x80},
	{0x03, 0x03, 0x07, 0x9F, 0x80},
	{0x03, 0x03, 0x07, 0x5F, 0x80},
	{0x03, 0x03, 0x07, 0xDF, 0x80},
	{0x03, 0x03, 0x07, 0x3F, 0x80},
	{0x03, 0x03, 0x07, 0xBF, 0x80},
	{0x03, 0x03, 0x07, 0x7F, 0x80},
	{0x03, 0x03, 0x07, 0xFF, 0x80},
}
