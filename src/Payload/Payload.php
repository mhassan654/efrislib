<?php

namespace Sniper\EfrisLib\Payload;

use JsonSerializable;
use Sniper\EfrisLib\Builder;
use Sniper\EfrisLib\Crypto2;

/**
 * @template T of Payload
 */
class Payload implements JsonSerializable
{
    public function __construct(public ?GlobalInfo $globalInfo, public ReturnStateInfo $returnStateInfo = new ReturnStateInfo(), public Data $data=new Data())
    {}


    /**
     * @param string $aesKey
     * @return $this
     */
    public function encrypt(string $aesKey): Payload
    {
        $this->data->content = Crypto2::aesEncrypt($this->data->content, $aesKey);
        return $this;
    }

    public function decrypt(string $aesKey): Payload
    {
        $this->data->content = Crypto2::aesDecrypt($this->data->content, $aesKey);
        return $this;
    }

    public function jsonSerialize(): array
    {
        return ['data' => $this->data->jsonSerialize(), 'globalInfo' => $this->globalInfo->jsonSerialize(), 'returnStateInfo' => $this->returnStateInfo->jsonSerialize()];
    }

    public  static function fromJson(array $json): Payload
    {
        return new self(GlobalInfo::fromJson($json['globalInfo']), ReturnStateInfo::fromJson($json['returnStateInfo']), Data::fromJson($json['data']));
    }
}
