package http3

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/quic-go/qpack"
	mockquic "github.com/refraction-networking/uquic/internal/mocks/quic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Response Writer", func() {
	var (
		rw     *responseWriter
		strBuf *bytes.Buffer
	)

	BeforeEach(func() {
		strBuf = &bytes.Buffer{}
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Write(gomock.Any()).DoAndReturn(strBuf.Write).AnyTimes()
		str.EXPECT().SetReadDeadline(gomock.Any()).Return(nil).AnyTimes()
		str.EXPECT().SetWriteDeadline(gomock.Any()).Return(nil).AnyTimes()
		rw = newResponseWriter(newStream(str, nil, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
	})

	decodeHeader := func(str io.Reader) map[string][]string {
		rw.Flush()
		rw.flushTrailers()
		fields := make(map[string][]string)
		decoder := qpack.NewDecoder(nil)

		fp := frameParser{r: str}
		frame, err := fp.ParseNext()
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
		headersFrame := frame.(*headersFrame)
		data := make([]byte, headersFrame.Length)
		_, err = io.ReadFull(str, data)
		Expect(err).ToNot(HaveOccurred())
		hfs, err := decoder.DecodeFull(data)
		Expect(err).ToNot(HaveOccurred())
		for _, p := range hfs {
			fields[p.Name] = append(fields[p.Name], p.Value)
		}
		return fields
	}

	getData := func(str io.Reader) []byte {
		fp := frameParser{r: str}
		frame, err := fp.ParseNext()
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		df := frame.(*dataFrame)
		data := make([]byte, df.Length)
		_, err = io.ReadFull(str, data)
		Expect(err).ToNot(HaveOccurred())
		return data
	}

	It("writes status", func() {
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(2))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		Expect(fields).To(HaveKey("date"))
	})

	It("writes headers", func() {
		rw.Header().Add("content-length", "42")
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue("content-length", []string{"42"}))
	})

	It("writes multiple headers with the same name", func() {
		const cookie1 = "test1=1; Max-Age=7200; path=/"
		const cookie2 = "test2=2; Max-Age=7200; path=/"
		rw.Header().Add("set-cookie", cookie1)
		rw.Header().Add("set-cookie", cookie2)
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKey("set-cookie"))
		cookies := fields["set-cookie"]
		Expect(cookies).To(ContainElement(cookie1))
		Expect(cookies).To(ContainElement(cookie2))
	})

	It("writes data", func() {
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		// And foobar on the data stream
		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("writes data after WriteHeader is called", func() {
		rw.WriteHeader(http.StatusTeapot)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		// And foobar on the data stream
		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("does not WriteHeader() twice", func() {
		rw.WriteHeader(http.StatusOK)
		rw.WriteHeader(http.StatusInternalServerError)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(2))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(fields).To(HaveKey("date"))
	})

	It("allows calling WriteHeader() several times when using the 103 status code", func() {
		rw.Header().Add("Link", "</style.css>; rel=preload; as=style")
		rw.Header().Add("Link", "</script.js>; rel=preload; as=script")
		rw.WriteHeader(http.StatusEarlyHints)

		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())

		// Early Hints must have been received
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(2))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"103"}))
		Expect(fields).To(HaveKeyWithValue("link", []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}))

		// According to the spec, headers sent in the informational response must also be included in the final response
		fields = decodeHeader(strBuf)
		Expect(fields).To(HaveLen(4))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(fields).To(HaveKey("date"))
		Expect(fields).To(HaveKey("content-type"))
		Expect(fields).To(HaveKeyWithValue("link", []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		rw.WriteHeader(304)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
	})

	It("first call to Write sniffs if Content-Type is not set", func() {
		n, err := rw.Write([]byte("<html></html>"))
		Expect(n).To(Equal(13))
		Expect(err).ToNot(HaveOccurred())

		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue("content-type", []string{"text/html; charset=utf-8"}))
	})

	It(`is compatible with "net/http".ResponseController`, func() {
		Expect(rw.SetReadDeadline(time.Now().Add(1 * time.Second))).To(BeNil())
		Expect(rw.SetWriteDeadline(time.Now().Add(1 * time.Second))).To(BeNil())
	})

	It(`checks Content-Length header`, func() {
		rw.Header().Set("Content-Length", "6")
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).To(BeNil())

		n, err = rw.Write([]byte("foobar"))
		Expect(n).To(Equal(0))
		Expect(err).To(Equal(http.ErrContentLength))
	})

	It(`panics when writing invalid status`, func() {
		Expect(func() { rw.WriteHeader(99) }).To(Panic())
		Expect(func() { rw.WriteHeader(1000) }).To(Panic())
	})

	It("write announced trailer", func() {
		rw.Header().Add("Trailer", "Key")
		rw.WriteHeader(http.StatusTeapot)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		rw.Header().Set("Key", "Value")

		// writeTrailers needs to be called after writing the full body
		Expect(rw.writeTrailers()).ToNot(HaveOccurred())

		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		Expect(fields).To(HaveKeyWithValue("trailer", []string{"Key"}))
		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		fields = decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue("key", []string{"Value"}))
	})

	It("ignore non-announced trailer (without trailer prefix)", func() {
		rw.Header().Set("Trailer", "Key")
		rw.WriteHeader(200)
		rw.Write([]byte("foobar"))
		rw.Header().Set("UnknownKey", "Value")
		rw.Header().Set("Key", "Value")

		// Needs to call writeTrailers to simulate the end of the handler
		Expect(rw.writeTrailers()).ToNot(HaveOccurred())
		headers := decodeHeader(strBuf)
		Expect(headers).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(headers).To(HaveKeyWithValue("trailer", []string{"Key"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		trailers := decodeHeader(strBuf)
		Expect(trailers).To(HaveKeyWithValue("key", []string{"Value"}))
		Expect(trailers).To(Not(HaveKeyWithValue("unknownkey", []string{"Value"})))
	})

	It("write non-announced trailer (with trailer prefix)", func() {
		rw.Header().Set("Trailer", "Key")
		rw.WriteHeader(200)
		rw.Write([]byte("foobar"))
		rw.Header().Set("Key", "Value")
		rw.Header().Set(http.TrailerPrefix+"Key2", "Value")
		rw.Flush()

		// Needs to call writeTrailers to simulate the end of the handler
		Expect(rw.writeTrailers()).ToNot(HaveOccurred())
		headers := decodeHeader(strBuf)
		Expect(headers).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(headers).To(HaveKeyWithValue("trailer", []string{"Key"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		trailers := decodeHeader(strBuf)
		Expect(trailers).To(HaveKeyWithValue("key", []string{"Value"}))
		Expect(trailers).To(HaveKeyWithValue("key2", []string{"Value"}))
	})
})
