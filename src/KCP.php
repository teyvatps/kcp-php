<?php

namespace labalityowo\kcp;

use labalityowo\Bytebuffer\Buffer;

class KCP
{

    public const KCP_RTO_NDL = 30;
    public const KCP_RTO_MIN = 100;
    public const KCP_RTO_DEF = 200;
    public const KCP_RTO_MAX = 60000;

    public const KCP_CMD_PUSH = 81;
    public const KCP_CMD_ACK = 82;
    public const KCP_CMD_WASK = 83;
    public const KCP_CMD_WINS = 84;

    public const KCP_ASK_SEND = 1;
    public const KCP_ASK_TELL = 2;

    public const KCP_WND_SND = 32;
    public const KCP_WND_RCV = 256;

    public const KCP_MTU_DEF = 1400;

    public const KCP_INTERVAL = 100;
    public const KCP_OVERHEAD = 28;

    public const KCP_THRESH_INIT = 2;
    public const KCP_THRESH_MIN = 2;

    public const KCP_PROBE_INIT = 7000;
    public const KCP_PROBE_LIMIT = 120000;

    /// Maximun Transmission Unit
    private int $mtu;
    /// Maximum Segment Size
    private int $mss;
    /// Connection state
    private int $state;

    /// First unacknowledged packet
    private int $sndUna;
    /// Next packet
    private int $sndNxt;
    /// Next packet to be received
    private int $rcvNxt;

    /// Congetion window threshole
    private int $ssThresh;

    /// ACK receive variable RTT
    private int $rxRttVal;
    /// ACK receive static RTT
    private int $rxsRtt;
    /// Resend time (calculated by ACK delay time)
    private int $rxRto;
    /// Minimal resend timeout
    private int $rxMinRto;

    /// Send window
    private int $sndWnd;
    /// Receive window
    private int $rcvWnd;
    /// Remote receive window
    private int $rmtWnd;
    /// Congetion window
    private int $cWnd;
    /// Check window
    /// - IKCP_ASK_TELL, telling window size to remote
    /// - IKCP_ASK_SEND, ask remote for window size
    private int $probe;

    /// Last update time
    private int $current;
    /// Flush interval
    private int $interval;
    /// Next flush interval
    private int $tsFlush;

    /// Enable nodelay
    private bool $nodelay;
    /// Updated has been called or not
    private bool $updated;

    /// Next check window timestamp
    private int $tsProbe;
    /// Check window wait time
    private int $probeWait;

    /// Maximum resend time
    private int $deadLink;
    /// Maximum payload size
    private int $incr;

    private array $sndQueue = [];
    private array $rcvQueue = [];
    private array $sndBuf = [];
    private array $rcvBuf = [];

    /// Pending ACK
    private array $acklist = [];
    private Buffer $buf;

    /// ACK number to trigger fast resend
    private int $fastResend;
    /// Disable congetion control
    private bool $nocwnd;

    public function __construct(
        private readonly int $conv, // Conversation ID
        private readonly int $token, // User token
        private \Closure $output, //Output
        private bool $stream = false // Enable streamer mode
    )
    {
        $this->sndUna = 0;
        $this->sndNxt = 0;
        $this->rcvNxt = 0;
        $this->rxRttVal = 0;
        $this->rxsRtt = 0;
        $this->state = 0;
        $this->cWnd = 0;
        $this->probe = 0;
        $this->current = 0;
        $this->nodelay = false;
        $this->updated = false;
        $this->tsProbe = 0;
        $this->probeWait = 0;
        $this->deadLink = 10;
        $this->incr = 0;
        $this->fastResend = 0;
        $this->nocwnd = false;
        $this->sndWnd = self::KCP_WND_SND;
        $this->rcvWnd = self::KCP_WND_RCV;
        $this->rmtWnd = self::KCP_WND_RCV;
        $this->mtu = self::KCP_MTU_DEF;
        $this->mss = self::KCP_MTU_DEF - self::KCP_OVERHEAD;
        $this->buf = Buffer::allocate(self::KCP_MTU_DEF + self::KCP_OVERHEAD);
        $this->rxRto = self::KCP_RTO_DEF;
        $this->rxMinRto = self::KCP_RTO_MIN;
        $this->interval = self::KCP_INTERVAL;
        $this->tsFlush = self::KCP_INTERVAL;
        $this->ssThresh = self::KCP_THRESH_INIT;
    }

    public function peekSize(): int
    {
        $segment = $this->rcvQueue[0];
        if (!$segment instanceof Segment) {
            return -1;
        }

        if ($segment->getFrg() === 0) {
            return $segment->getData()->getLength();
        }

        if (count($this->rcvQueue) < $segment->getFrg() + 1) {
            return -1;
        }

        $len = 0;
        foreach ($this->rcvQueue as $segment){
            $len += $segment->getData()->getLength();
            if($segment->getFrg() === 0){
                break;
            }
        }
        return $len;
    }

    public function recv(Buffer &$buffer, int $offset = 0)
    {
        if (count($this->rcvQueue) === 0) {
            return -1;
        }

        $peekSize = $this->peekSize();
        if ($peekSize < 0) {
            return -2;
        }

        if ($peekSize > $buffer->getLength()) {
            return -3;
        }

        $recover = count($this->rcvQueue) >= $this->rcvWnd;
        while (($seg = array_shift($this->rcvQueue))) {
            $seg->getData()->copy($buffer, $offset);
            $offset += $seg->getData()->getLength();
            if ($seg->getFrg() === 0) {
                break;
            }
        }

        $this->moveBuf();

        if (count($this->rcvQueue) < $this->rcvWnd && $recover) {
            $this->probe |= self::KCP_ASK_TELL;
        }
        return $peekSize;
    }

    public function moveBuf()
    {
        while (count($this->rcvBuf) !== 0) {
            $nrcvQueue = count($this->rcvQueue);
            $seg = $this->rcvBuf[0];
            if ($seg->getSn() === $this->rcvNxt && $nrcvQueue < $this->rcvWnd) {
                $this->rcvNxt += 1;
            } else {
                break;
            }
            array_shift($this->rcvBuf);
            array_push($this->rcvQueue, $seg);
        }
    }

    private function shrinkBuf()
    {
        $seg = $this->sndBuf[0] ?? null;
        if ($seg instanceof Segment) {
            $this->sndUna = $seg->getSn();
        } else {
            $this->sndUna = $this->sndNxt;
        }
    }

    private function parseAck(int $sn)
    {
        if ($sn - $this->sndUna < 0 || $sn - $this->sndNxt >= 0) {
            return;
        }
        $bufSize = count($this->sndBuf);
        for ($i = 0; $i < $bufSize; $i++) {
            $seg = $this->sndBuf[$i];
            if ($seg->getSn() === $sn) {
                unset($this->sndBuf[$i]);
            } else {
                if ($sn < $seg->getSn()) {
                    break;
                }
            }
        }
    }

    private function parseUna(int $una)
    {
        while (count($this->sndBuf) !== 0) {
            $seg = $this->sndBuf[0];
            if ($una - $seg->getSn() > 0) {
                array_shift($this->sndBuf);
            } else {
                break;
            }
        }
    }

    private function parseFastAck(int $sn)
    {
        if ($sn - $this->sndUna < 0 || $sn - $this->sndNxt >= 0) {
            return;
        }
        foreach ($this->sndBuf as $seg) {
            if ($sn - $seg->getSn() < 0) {
                break;
            } else {
                if ($sn !== $seg->getSn()) {
                    $seg->setFastAck($seg->getFastAck() + 1);
                }
            }
        }
    }

    private function ackPush(int $sn, int $ts)
    {
        array_push($this->acklist, [$sn, $ts]);
    }

    private function parseData(Segment $newSeg)
    {
        if ($newSeg->getSn() - ($this->rcvNxt + $this->rcvWnd) >= 0 || $newSeg->getSn() - $this->rcvNxt < 0) {
            return;
        }
        $repeat = false;
        $newIndex = count($this->rcvBuf);
        for ($i = count($this->rcvBuf) - 1; $i >= 0; $i--) {
            $segment = $this->rcvBuf[$i];
            if ($segment->getSn() === $newSeg->getSn()) {
                $repeat = true;
                break;
            } else {
                if ($newSeg->getSn() - $segment->getSn() > 0) {
                    break;
                }
            }
            $newIndex -= 1;
        }

        if (!$repeat) {
            array_splice($this->rcvBuf, $newIndex, 0, [$newSeg]);
        }

        $this->moveBuf();
    }

    public function send(Buffer $buffer)
    {
        $sentSize = 0;
        if ($this->stream) {
            $old = $this->sndQueue[array_key_last($this->sndQueue)];
            if ($old instanceof Segment) {
                $l = $old->getData()->getLength();
                if ($l < $this->mss) {
                    $capacity = $this->mss - $l;
                    $extend = min($buffer->getLength(), $capacity);
                    $lf = $buffer->slice(0, $extend);
                    $rt = $buffer->slice($extend);
                    $old->setData(Buffer::concat([$old->getData(), $lf]));
                    $buffer = $rt;
                    $old->setFrg(0);
                    $sentSize += $extend;
                }
                if ($buffer->getLength() === 0) {
                    return $sentSize;
                }
            }
        }

        if ($buffer->getLength() <= $this->mss) {
            $count = 1;
        } else {
            $count = (($buffer->getLength() + $this->mss - 1) / $this->mss);
        }
        if ($count >= self::KCP_WND_RCV) {
            return -2;
        }

        for ($i = 0; $i < $count; $i++) {
            $size = min($this->mss, $buffer->getLength());
            $lf = $buffer->slice(0, $size);
            $rt = $buffer->slice($size);
            $newSeg = new Segment($lf);
            $buffer = $rt;
            if ($this->stream) {
                $newSeg->setFrg(0);
            } else {
                $newSeg->setFrg($count - $i - 1);
            }
            array_push($this->sndQueue, $newSeg);
            $sentSize += $size;
        }
        return $sentSize;
    }

    private function updateAck(int $rtt)
    {
        if ($this->rxsRtt === 0) {
            $this->rxsRtt = $rtt;
            $this->rxRttVal = ($rtt / 2);
        } else {
            if ($rtt > $this->rxsRtt) {
                $delta = $rtt - $this->rxsRtt;
            } else {
                $delta = $this->rxsRtt - $rtt;
            }

            $this->rxRttVal = ((3 * $this->rxRttVal + $delta) / 4);
            $this->rxsRtt = ((7 * $this->rxsRtt + $rtt) / 8);

            if ($this->rxsRtt < 1) {
                $this->rxsRtt = 1;
            }
        }

        $rto = $this->rxsRtt + max($this->interval, 4 * $this->rxRttVal);
        $this->rxRto = max($this->rxMinRto, min($rto, self::KCP_RTO_MAX));
    }

    public function input(Buffer $buffer)
    {
        if ($buffer->getLength() < self::KCP_OVERHEAD) {
            return -1;
        }
        $totalRead = 0;
        $flag = false;
        $maxAck = 0;
        $oldUna = $this->sndUna;
        while ($buffer->getLength() >= self::KCP_OVERHEAD) {
            $conv = $buffer->readUInt32LE();
            $token = $buffer->readUInt32LE(4);
            $cmd = $buffer->readUInt8(8);
            $frg = $buffer->readUInt8(9);
            $wnd = $buffer->readUInt16LE(10);
            $ts = $buffer->readUInt16LE(12);
            $sn = $buffer->readUInt16LE(16);
            $una = $buffer->readUInt16LE(20);
            $len = $buffer->readUInt16LE(24);
            if ($conv !== $this->conv || $token !== $this->token) {
                return -1;
            }
            if ($buffer->getLength() - self::KCP_OVERHEAD < $len) {
                return -2;
            }
            switch ($cmd) {
                case self::KCP_CMD_PUSH:
                case self::KCP_CMD_ACK:
                case self::KCP_CMD_WASK:
                case self::KCP_CMD_WINS:
                    break;
                default:
                    return -3;
            }
            $this->rmtWnd = $wnd;
            $this->parseUna($una);
            $this->shrinkBuf();
            switch ($cmd) {
                case self::KCP_CMD_ACK:
                    $rtt = $this->current - $ts;
                    if ($rtt >= 0) {
                        $this->updateAck($rtt);
                    }
                    $this->parseAck($sn);
                    $this->shrinkBuf();
                    if (!$flag) {
                        $maxAck = $sn;
                        $flag = true;
                    } else {
                        if ($sn - $maxAck > 0) {
                            $maxAck = $sn;
                        }
                    }
                    break;
                case self::KCP_CMD_PUSH:
                    if ($sn - ($this->rcvNxt + $this->rcvWnd) < 0) {
                        $this->ackPush($sn, $ts);
                        if ($sn - $this->rcvNxt >= 0) {
                            $sbuf = $buffer->slice(self::KCP_OVERHEAD, self::KCP_OVERHEAD + $len);
                            $segment = new Segment($sbuf);
                            $segment->setConv($conv);
                            $segment->setToken($token);
                            $segment->setCmd($cmd);
                            $segment->setFrg($frg);
                            $segment->setWnd($wnd);
                            $segment->setTs($ts);
                            $segment->setSn($sn);
                            $segment->setUna($una);
                            $this->parseData($segment);
                        }
                    }
                    break;
                case self::KCP_CMD_WASK:
                    $this->probe |= self::KCP_ASK_TELL;
                    break;

                case self::KCP_CMD_WINS:
                    break;
            }
            $totalRead += self::KCP_OVERHEAD + $len;
            $buffer = $buffer->slice(self::KCP_OVERHEAD + $len);
        }
        if ($flag) {
            $this->parseFastAck($maxAck);
        }
        if ($this->sndUna > $oldUna && $this->cWnd < $this->rmtWnd) {
            $mss = $this->mss;
            if ($this->cWnd < $this->ssThresh) {
                $this->cWnd += 1;
                $this->incr += $mss;
            } else {
                if ($this->incr < $mss) {
                    $this->incr = $mss;
                }
                $this->incr += (($mss * $mss) / $this->incr) + ($mss / 16);
                if (($this->cWnd + 1) * $mss <= $this->incr) {
                    $this->cWnd += 1;
                }
            }
            if ($this->cWnd > $this->rmtWnd) {
                $this->cWnd = $this->rmtWnd;
                $this->incr = $this->rmtWnd * $mss;
            }
        }
        return $totalRead;
    }

    private function wndUnused(): int
    {
        if (count($this->rcvQueue) < $this->rcvWnd) {
            return $this->rcvWnd - count($this->rcvQueue);
        } else {
            return 0;
        }
    }

    public function flush(){
        if (!$this->updated) {
            return;
        }
        $segment = new Segment(Buffer::allocate(0));
        $segment->setConv($this->conv);
        $segment->setCmd(self::KCP_CMD_ACK);
        $segment->setWnd($this->wndUnused());
        $segment->setUna($this->rcvNxt);
        $segment->setToken($this->token);
        $writeIndex = 0;
        foreach ($this->acklist as [$sn, $ts]){
            $this->makeSpace($writeIndex, self::KCP_OVERHEAD);
            $segment->setSn($sn);
            $segment->setTs($ts);
            $writeIndex += $segment->encode($this->buf, $writeIndex);
        }
        $this->acklist = [];

        if ($this->rmtWnd === 0) {
            if ($this->probeWait === 0) {
                $this->probeWait = self::KCP_PROBE_INIT;
                $this->tsProbe = $this->current + $this->probeWait;
            } else {
                if ($this->current - $this->tsProbe >= 0 && $this->probeWait < self::KCP_PROBE_INIT) {
                    $this->probeWait += self::KCP_PROBE_INIT;
                }
            }
        } else {
            $this->probeWait += ($this->probeWait / 2);
            if ($this->probeWait > self::KCP_PROBE_LIMIT) {
                $this->probeWait = self::KCP_PROBE_LIMIT;
            }
            $this->tsProbe = $this->current + $this->probeWait;
            $this->probe |= self::KCP_ASK_SEND;
        }

        if (($this->probe & self::KCP_ASK_SEND) != 0)
        {
            $segment->setCmd(self::KCP_CMD_WASK);
        }

        if (($this->probe & self::KCP_ASK_TELL) != 0)
        {
            $segment->setCmd(self::KCP_CMD_WINS);
        }
        $this->makeSpace($writeIndex, self::KCP_OVERHEAD);
        $writeIndex += $segment->encode($this->buf, $writeIndex);
        $this->probe = 0;
        $cWnd = min($this->sndWnd, $this->rmtWnd);
        if ($this->nocwnd) {
            $cWnd = min($this->cWnd, $cWnd);
        }
        while ($this->sndNxt - ($this->sndUna + $cWnd) < 0) {
            $newSegment = array_shift($this->sndQueue);
            if (!$newSegment instanceof Segment) {
                break;
            }
            $newSegment->setConv($this->conv);
            $newSegment->setToken($this->token);
            $newSegment->setCmd(self::KCP_CMD_PUSH);
            $newSegment->setWnd($segment->getWnd());
            $newSegment->setTs($this->current);
            $newSegment->setSn($this->sndNxt);
            $this->sndNxt++;
            $newSegment->setUna($this->rcvNxt);
            $newSegment->setResendTs($this->current);
            $newSegment->setRto($this->rxRto);
            $newSegment->setFastAck(0);
            $newSegment->setXmit(0);
            array_push($this->sndBuf, $newSegment);
        }
        $resent = $this->fastResend > 0 ? $this->fastResend : 0xffffffff;
        $rtoMin = !$this->nodelay ? ($this->rxRto >> 3) : 0;
        $lost = false;
        $change = 0;
        foreach ($this->sndBuf as $sndSegment) {
            if (!$sndSegment instanceof Segment) {
                continue;
            }
            $needSend = false;
            if ($sndSegment->getXmit() === 0) {
                $needSend = true;
                $sndSegment->setXmit($sndSegment->getXmit() + 1);
                $sndSegment->setRto($this->rxRto);
                $sndSegment->setResendTs($this->current + $rtoMin + $sndSegment->getRto());
            } else {
                if ($this->current - $sndSegment->getResendTs() >= 0) {
                    $needSend = true;
                    $sndSegment->setXmit($sndSegment->getXmit() + 1);
                    if (!$this->nodelay) {
                        $sndSegment->setRto($sndSegment->getRto() + $this->rxRto);
                    } else {
                        $sndSegment->setRto($sndSegment->getRto() + ($this->rxRto / 2));
                    }
                    $sndSegment->setResendTs($this->current + $sndSegment->getRto());
                    $lost = true;
                } else {
                    if ($sndSegment->getFastAck() >= $resent) {
                        $needSend = true;
                        $sndSegment->setXmit($sndSegment->getXmit() + 1);
                        $sndSegment->setFastAck(0);
                        $sndSegment->setResendTs($this->current + $sndSegment->getRto());
                        $change += 1;
                    }
                }
            }
            if ($needSend) {
                $sndSegment->setTs($this->current);;
                $sndSegment->setWnd($segment->getWnd());
                $sndSegment->setUna($this->rcvNxt);

                $need = self::KCP_OVERHEAD + $sndSegment->getData()->getLength();
                $this->makeSpace($writeIndex, $need);
                $writeIndex += $sndSegment->encode($this->buf, $writeIndex);

                if ($sndSegment->getXmit() >= $this->deadLink) {
                    $this->state = -1;
                }
            }
        }
        $this->flushBuffer($writeIndex);
        if ($change > 0) {
            $inflight = ($this->sndNxt - $this->sndUna);
            $this->ssThresh = $inflight / 2;
            if ($this->ssThresh < self::KCP_THRESH_MIN) {
                $this->ssThresh = self::KCP_THRESH_MIN;
            }
            $this->cWnd = $this->ssThresh + $resent;
            $this->incr = $this->cWnd * $this->mss;
        }
        if ($lost) {
            $this->ssThresh = ($cWnd / 2);
            if ($this->ssThresh < self::KCP_THRESH_MIN) {
                $this->ssThresh = self::KCP_THRESH_MIN;
            }
            $this->cWnd = 1;
            $this->incr = $this->mss;
        }

        if ($this->cWnd < 1) {
            $this->cWnd = 1;
            $this->incr = $this->mss;
        }
    }

    private function makeSpace(int &$index, int $space): void
    {
        if($index + $space > $this->mtu){
            ($this->output)($this->buf->slice(0, $index));
            $index = 0;
        }
    }

    private function flushBuffer(int &$index): void
    {
        if($index > 0){
            ($this->output)($this->buf->slice(0, $index));
        }
    }

    public function update(int $current)
    {
        $this->current = $current;
        if(!$this->updated) {
            $this->updated = true;
            $this->tsFlush = $this->current;
        }
        $slap = $this->current - $this->tsFlush;
        if($slap >= 10000 || $slap < -10000) {
            $this->tsFlush = $this->current;
            $slap = 0;
        }
        if($slap >= 0) {
            $this->tsFlush += $this->interval;
            if($this->current - $this->tsFlush >= 0) {
                $this->tsFlush = $this->current + $this->interval;
            }
            $this->flush();
        }
    }

    public function check(int $current)
    {
        if (!$this->updated) {
            return 0;
        }
        $tsFlush = $this->tsFlush;
        $tmPacket = 0xffffffff;

        if ($current - $tsFlush >= 10000 || $current - $tsFlush < -10000) {
            $tsFlush = $current;
        }

        if ($current - $tsFlush >= 0) {
            return 0;
        }

        $tmFlush = $tsFlush - $current;
        foreach ($this->sndBuf as $seg){
            $diff = $seg->getResendTs() - $current;
            if($diff <= 0) return 0;
            if($diff < $tmPacket) $tmPacket = $diff;
        }
        return min($tmPacket, $tmFlush, $this->interval);
    }

    public function setMtu(int $mtu)
    {
        $mtu = max($mtu, 50, self::KCP_OVERHEAD);
        $this->mtu = $mtu;
        $this->mss = $mtu - self::KCP_OVERHEAD;
        $this->buf = Buffer::allocate(($mtu + self::KCP_OVERHEAD) * 3);
    }

    public function setInterval(int $interval)
    {
        $this->interval = max(10, min($interval, 5000));
    }

    public function setNodelay(bool $nodelay, int $resend, bool $nc){
        $this->nodelay = $nodelay;
        if($nodelay){
            $this->rxMinRto = self::KCP_RTO_NDL;
        }else{
            $this->rxMinRto = self::KCP_RTO_MIN;
        }

        $this->fastResend = max(0, $resend);
        $this->nocwnd = $nc;
    }

    public function setWndSize(int $sndWnd, int $rcvWnd){
        $this->sndWnd = $sndWnd;
        $this->rcvWnd = max($rcvWnd, self::KCP_WND_RCV);
    }

    public function getWaitSnd()
    {
        return count($this->sndBuf) + count($this->sndQueue);
    }

    public function getSndWnd(){
        return $this->sndWnd;
    }

    public function getRcvWnd(){
        return $this->rcvWnd;
    }

    public function setRxMinRto(int $rxMinRto): void
    {
        $this->rxMinRto = $rxMinRto;
    }

    public function setFastResend(int $fastResend): void
    {
        $this->fastResend = $fastResend;
    }

    public function getHeaderLen(){
        return self::KCP_OVERHEAD;
    }

    public function isStream(): bool
    {
        return $this->stream;
    }

    public function getMss(): int
    {
        return $this->mss;
    }

    public function setMaxResend(int $deadLink){
        $this->deadLink = $deadLink;
    }

    public function isDeadLink(): bool
    {
        return $this->state !== 0;
    }
}