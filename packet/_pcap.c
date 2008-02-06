/*
 Copyright (c) 2003-2008, Nullcube Pty Ltd
 All rights reserved.
 
 Permission is hereby granted, free of charge, to any person obtaining a
 copy of this software and associated documentation files (the "Software"), to
 deal in the Software without restriction, including without limitation the
 rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/

#include <Python.h>
#include <sys/types.h>
#include <pcap.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
/*
 *  Todo:
 *      - pcap_file, pcap_next?
 */

#ifndef LINUX2
    extern int errno;
#endif

static PyObject *PcapError;
jmp_buf JENV;

static PyObject *open_live(PyObject *self, PyObject *args){
    char *device;
    int snaplen, promisc, to_ms;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *ret;

    if (!PyArg_ParseTuple(args, "siii", &device, &snaplen, &promisc, &to_ms))
        return NULL;

    ret = pcap_open_live(device, snaplen, promisc, to_ms, ebuf);
    if (!ret){
        PyErr_SetString(PcapError, ebuf);
        return NULL;
    }
    return PyCObject_FromVoidPtr((void*)ret, NULL);
}

static PyObject *dump_open(PyObject *self, PyObject *args){
    PyObject *ptr;
    char *filename;
    pcap_dumper_t *dumper;
    pcap_t *pptr;

    if (!PyArg_ParseTuple(args, "Os", &ptr, &filename))
        return NULL;
    pptr = (pcap_t*)PyCObject_AsVoidPtr(ptr);
    dumper = pcap_dump_open(pptr, filename);
    if (!dumper){
        PyErr_SetString(PcapError, pcap_geterr(pptr));
        return NULL;
    }
    return PyCObject_FromVoidPtr((void*)dumper, NULL);
}


static PyObject *dump_ftell(PyObject *self, PyObject *args){
    PyObject *dptr;
    int offset; 
    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    offset = pcap_dump_ftell((pcap_dumper_t*)PyCObject_AsVoidPtr(dptr));
    return Py_BuildValue("l", offset);
}


static PyObject *open_offline(PyObject *self, PyObject *args){
    char ebuf[PCAP_ERRBUF_SIZE];
    char *filename;
    pcap_t *ret;

    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    ret = pcap_open_offline(filename, ebuf);
    if (!ret){
        PyErr_SetString(PcapError, ebuf);
        return NULL;
    }
    return PyCObject_FromVoidPtr((void*)ret, NULL);
}


static PyObject *open_dead(PyObject *self, PyObject *args){
    int linktype, snaplen;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *ret;

    if (!PyArg_ParseTuple(args, "ii", &linktype, &snaplen))
        return NULL;

    ret = pcap_open_dead(linktype, snaplen);
    if (!ret){
        PyErr_SetString(PcapError, ebuf);
        return NULL;
    }
    return PyCObject_FromVoidPtr((void*)ret, NULL);
}


static PyObject *dump_close(PyObject *self, PyObject *args){
    PyObject *dptr;
    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    pcap_dump_close((pcap_dumper_t*)PyCObject_AsVoidPtr(dptr));
    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *closeptr(PyObject *self, PyObject *args){
    PyObject *ptr;
    if (!PyArg_ParseTuple(args, "O", &ptr))
        return NULL;

    pcap_close((pcap_t*)PyCObject_AsVoidPtr(ptr));
    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *datalink(PyObject *self, PyObject *args){
    PyObject *ptr;
    int linktype; 
    if (!PyArg_ParseTuple(args, "O", &ptr))
        return NULL;

    linktype = pcap_datalink((pcap_t*)PyCObject_AsVoidPtr(ptr));
    return Py_BuildValue("i", linktype);
}


static void callback(u_char *user, const struct pcap_pkthdr *phdr, const u_char *data){
    PyObject *packetstr;
    PyObject *tstamptuple, *argstuple;

    packetstr = PyString_FromStringAndSize((const char*)data, phdr->caplen);
    if (packetstr == NULL)
        longjmp(JENV, 1);
    tstamptuple = Py_BuildValue("(ll)", (long)phdr->ts.tv_sec, (long)phdr->ts.tv_usec);
    if (tstamptuple == NULL)
        longjmp(JENV, 1);
    argstuple = Py_BuildValue("(OOl)", packetstr, tstamptuple, (long)phdr->len);
    if (argstuple == NULL)
        longjmp(JENV, 1);
    if (PyObject_CallObject((PyObject*)user, argstuple) == NULL)
        longjmp(JENV, 1);
	if (PyErr_CheckSignals())
        longjmp(JENV, 1);

    Py_DECREF(packetstr);
    Py_DECREF(tstamptuple);
    Py_DECREF(argstuple);
}

static PyObject *dispatch(PyObject *self, PyObject *args){
    PyObject *ptr, *callable;
    pcap_t *pptr;
    int cnt;
    if (!PyArg_ParseTuple(args, "OiO", &ptr, &cnt, &callable))
        return NULL;

    if (sigsetjmp(JENV, 1)){
        return NULL;
    }

    pptr = (pcap_t*)PyCObject_AsVoidPtr(ptr);
    if (pcap_dispatch(pptr, cnt, &callback, (u_char*)callable) < 0){
        PyErr_SetString(PcapError, pcap_geterr(pptr));
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *loop(PyObject *self, PyObject *args){
    PyObject *ptr, *callable;
    pcap_t *pptr;
    int cnt;

    if (!PyArg_ParseTuple(args, "OiO", &ptr, &cnt, &callable))
        return NULL;

    if (setjmp(JENV)){
        return NULL;
    }
    pptr = (pcap_t*)PyCObject_AsVoidPtr(ptr);
    if (pcap_loop(pptr, cnt, &callback, (u_char*)callable) < 0){
        PyErr_SetString(PcapError, pcap_geterr(pptr));
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

# if defined(OPENBSD4) | defined(LINUX2)
static PyObject *inject(PyObject *self, PyObject *args){
    PyObject *ptr;
    char *packet;
    int len;
    int ret;

    if (!PyArg_ParseTuple(args, "Os#", &ptr, &packet, &len))
        return NULL;
    ret = pcap_inject((pcap_t*)PyCObject_AsVoidPtr(ptr), packet, len);
    if (ret < 0){
        PyErr_SetString(PcapError, strerror(errno));
        return NULL;
    }
    return Py_BuildValue("i", ret);
}
#endif


static PyObject *dump(PyObject *self, PyObject *args){
    PyObject *dptr; 
    struct pcap_pkthdr phdr;
    u_char *packet;
    int datalen;
    int len;
    u_int32_t sec, usec;

    if (!PyArg_ParseTuple(args, "Os#(ii)i", &dptr, &packet, &datalen, &sec, &usec, &len))
        return NULL;

    /* First, we re-construct a pkthdr: */
    phdr.ts.tv_sec = sec;
    phdr.ts.tv_usec = usec;
    phdr.caplen = datalen;
    phdr.len = len;
    pcap_dump((u_char*)PyCObject_AsVoidPtr(dptr), &phdr, packet);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *lookupdev(PyObject *self, PyObject *args){
    char ebuf[PCAP_ERRBUF_SIZE];
    char *devstr;
    PyObject *pdevstr;

    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    devstr = pcap_lookupdev(ebuf);
    if (devstr == NULL){
        PyErr_SetString(PcapError, ebuf);
        return NULL;
    }
    pdevstr = PyString_FromString(devstr);
    if (pdevstr == NULL){
        PyErr_SetString(PcapError, "Could not retrieve device string.");
        return NULL;
    }
    return pdevstr;
}


static PyObject *lookupnet(PyObject *self, PyObject *args){
    char ebuf[PCAP_ERRBUF_SIZE];
    char *devstr;
    bpf_u_int32 netp, maskp;

    if (!PyArg_ParseTuple(args, "s", &devstr))
        return NULL;

    if (pcap_lookupnet(devstr, &netp, &maskp, ebuf) < 0){
        PyErr_SetString(PcapError, ebuf);
        return NULL;
    }
    return Py_BuildValue("(l, l)", netp, maskp);
}

/*
 * A wrapper for pcap_freecode that obeys the interface expected for the
 * destructor of a PyCObject.
 */
void freecode_wrapper(void *code){
	pcap_freecode((struct bpf_program*)code); 
	return; 
}

/*
 * Returns a Python object containing a pointer to a malloced bpf_program. The
 * user must explicitly free this using freebpf after use.
 */
static PyObject *compile(PyObject *self, PyObject *args){
    PyObject *pcap_ptr;
    char *bpfstr;
    pcap_t *pptr;
    int optimise;
    bpf_u_int32 netmask;
    struct bpf_program *bptr;

    if (!PyArg_ParseTuple(args, "Osii", &pcap_ptr, &bpfstr, &optimise, &netmask))
        return NULL;

    bptr = malloc(sizeof(struct bpf_program));
    if (!bptr){
        PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for BPF program.");
        return NULL;
    }
    pptr = (pcap_t*)PyCObject_AsVoidPtr(pcap_ptr);

    if (pcap_compile(pptr, bptr, bpfstr, optimise, netmask) < 0){
        PyErr_SetString(PcapError, "Filter program compilation error.");
        return NULL;
    }
    return PyCObject_FromVoidPtr((void*)bptr, freecode_wrapper);
}

static PyObject *setfilter(PyObject *self, PyObject *args){
    PyObject *ptr, *bpf;
    pcap_t *pptr;
    struct bpf_program *pbpf;

    if (!PyArg_ParseTuple(args, "OO", &ptr, &bpf))
        return NULL;

    pptr = (pcap_t*)PyCObject_AsVoidPtr(ptr);
    pbpf = (struct bpf_program*)PyCObject_AsVoidPtr(bpf);

    if (pcap_setfilter(pptr, pbpf) < 0){
        PyErr_SetString(PcapError, pcap_geterr(pptr));
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *snapshot(PyObject *self, PyObject *args){
    PyObject *dptr;
    int snaplen;

    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    snaplen = pcap_snapshot((pcap_t*)PyCObject_AsVoidPtr(dptr));
    return Py_BuildValue("i", snaplen);
}

static PyObject *is_swapped(PyObject *self, PyObject *args){
    PyObject *dptr;
    int swapped;

    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    swapped = pcap_is_swapped((pcap_t*)PyCObject_AsVoidPtr(dptr));
    return Py_BuildValue("i", swapped);
}

static PyObject *version(PyObject *self, PyObject *args){
    PyObject *dptr;
    int major, minor;

    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    major = pcap_major_version((pcap_t*)PyCObject_AsVoidPtr(dptr));
    minor = pcap_minor_version((pcap_t*)PyCObject_AsVoidPtr(dptr));

    return Py_BuildValue("(i, i)", major, minor);
}


static PyObject *stats(PyObject *self, PyObject *args){
    PyObject *ptr;
    struct pcap_stat pstat; 

    if (!PyArg_ParseTuple(args, "O", &ptr))
        return NULL;

    if (pcap_stats((pcap_t*)PyCObject_AsVoidPtr(ptr), &pstat) < 0){
        PyErr_SetString(PcapError, strerror(errno));
        return NULL;
    }
    return Py_BuildValue("{s:i, s:i, s:i}", "ps_recv", (int)pstat.ps_recv, 
                                            "ps_drop", (int)pstat.ps_drop, 
                                            "ps_ifdrop", (int)pstat.ps_ifdrop);
}


static PyObject *pfileno(PyObject *self, PyObject *args){
    PyObject *dptr;
	FILE *f;

    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    f = pcap_file((pcap_t*)PyCObject_AsVoidPtr(dptr));
    return Py_BuildValue("i", fileno(f));
}


static PyObject *pftell(PyObject *self, PyObject *args){
    PyObject *dptr;
	FILE *f;

    if (!PyArg_ParseTuple(args, "O", &dptr))
        return NULL;

    f = pcap_file((pcap_t*)PyCObject_AsVoidPtr(dptr));
    return Py_BuildValue("l", ftell(f));
}


static PyMethodDef PcapMethods[] = {
    {"open_live",       open_live,      METH_VARARGS,   "Open a device."},
    {"dump_open",       dump_open,      METH_VARARGS,   "Open a dump file."},
    {"open_offline",    open_offline,   METH_VARARGS,   "Open a file for reading."},
    {"open_dead",       open_dead,   METH_VARARGS,      "Open a dead feed."},
    {"close",           closeptr,       METH_VARARGS,   "Close a pointer."},
    {"dump_close",      dump_close,     METH_VARARGS,   "Close a dump file."},
    {"dump_ftell",      dump_ftell,     METH_VARARGS,   "Get current dumper file offset."},
    {"datalink",        datalink,       METH_VARARGS,   "Get the link layer type."},
    {"dispatch",        dispatch,       METH_VARARGS,   "Dispatch."},
	{"loop",            loop,           METH_VARARGS,   "Loop."},
#ifndef DARWIN
	{"inject",          inject,         METH_VARARGS,   "Inject a packet."},
#endif
    {"dump",            dump,           METH_VARARGS,   "Dump."},
    {"lookupdev",       lookupdev,      METH_VARARGS,   "Lookup a device."},
    {"lookupnet",       lookupnet,      METH_VARARGS,   "Lookup the network specifications of a device."},
    {"compile",         compile,        METH_VARARGS,   "Compile a BPF program."},
    {"setfilter",       setfilter,      METH_VARARGS,   "Set a filter."},
    {"snapshot",        snapshot,       METH_VARARGS,   "Return the snapshot length passed to pcap_live."},
    {"is_swapped",      is_swapped,     METH_VARARGS,   "True if the current savefile uses a different byte order than the current system."},
    {"fileno",			pfileno,		METH_VARARGS,   "Returns the file descriptor number of the current file."},
    {"ftell",			pftell,		METH_VARARGS,   "Returns the file position for an offline feed."},
    {"version",         version,        METH_VARARGS,   "Return the major and minor version of the pcap used to write the save file."},
    {"stats",           stats,          METH_VARARGS,   "Get stats for the feed."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


void init_pcap(void){
    PyObject *module, *global;
    module = Py_InitModule4("_pcap", PcapMethods, NULL, NULL, PYTHON_API_VERSION);
	global = PyImport_ImportModule("_global");
	if (NULL != global) {
		PcapError = PyObject_GetAttrString(global, "PcapError");
	}
}
